//! Progressive Huffman JPEG scans accumulate quantized coefficients.
//! The final dequantization, IDCT and pixel conversion are shared with the
//! baseline decoder. Each input scan has a strict entropy/restart boundary.

use super::{idct_block, planes_to_image, Component, DecodedImage, HuffTable, Plane, ZIGZAG};

const MAX_COEFFICIENTS: usize = 24 * 1024 * 1024;
const MAX_SCANS: usize = 128;

struct ComponentBlocks {
    stride: usize,
    rows: usize,
    blocks: Vec<[i16; 64]>,
    successive: [Option<u8>; 64],
}

pub(super) struct Progressive {
    components: Vec<ComponentBlocks>,
    mcu: (usize, usize),
    sampling: (usize, usize),
    size: (usize, usize),
    scans: usize,
}

impl Progressive {
    pub(super) fn new(width: usize, height: usize, specs: &[Component]) -> Option<Self> {
        let hmax = specs.iter().map(|c| c.h).max()?;
        let vmax = specs.iter().map(|c| c.v).max()?;
        let mcu = (width.div_ceil(8 * hmax), height.div_ceil(8 * vmax));
        let mut count = 0usize;
        let mut components = Vec::with_capacity(specs.len());
        for comp in specs {
            let stride = mcu.0.checked_mul(comp.h)?;
            let rows = mcu.1.checked_mul(comp.v)?;
            let n = stride.checked_mul(rows)?;
            count = count.checked_add(n.checked_mul(64)?)?;
            if count > MAX_COEFFICIENTS {
                return None;
            }
            components.push(ComponentBlocks {
                stride,
                rows,
                blocks: vec![[0; 64]; n],
                successive: [None; 64],
            });
        }
        Some(Self {
            components,
            mcu,
            sampling: (hmax, vmax),
            size: (width, height),
            scans: 0,
        })
    }

    pub(super) fn scan(
        &mut self,
        headers: &[u8],
        data: &[u8],
        specs: &[Component],
        dc: &[Option<HuffTable>],
        ac: &[Option<HuffTable>],
        restart: usize,
    ) -> Option<usize> {
        if self.scans >= MAX_SCANS {
            return None;
        }
        self.scans += 1;
        let n = usize::from(*headers.first()?);
        if n == 0 || n > specs.len() || headers.len() != 1 + 2 * n + 3 {
            return None;
        }
        let start = usize::from(*headers.get(1 + 2 * n)?);
        let end = usize::from(*headers.get(2 + 2 * n)?);
        let approx = *headers.get(3 + 2 * n)?;
        let (before, after) = (approx >> 4, approx & 15);
        if end >= 64
            || start > end
            || before > 13
            || after > 13
            || before != 0 && before != after + 1
            || start == 0 && end != 0
            || start != 0 && n != 1
        {
            return None;
        }
        let mut comps = Vec::<(usize, usize, usize)>::with_capacity(n);
        for pair in headers.get(1..1 + 2 * n)?.chunks_exact(2) {
            let ci = specs.iter().position(|c| c.id == pair[0])?;
            if comps.iter().any(|comp| comp.0 == ci) || pair[1] >> 4 > 3 || pair[1] & 15 > 3 {
                return None;
            }
            let component = self.components.get_mut(ci)?;
            if start != 0 && component.successive[0].is_none() {
                return None;
            }
            for slot in component.successive.get_mut(start..=end)? {
                let first = before == 0;
                if first && slot.is_some() || !first && *slot != Some(before) {
                    return None;
                }
                *slot = Some(after);
            }
            comps.push((ci, (pair[1] >> 4) as usize, (pair[1] & 15) as usize));
        }

        let grid = if let [(ci, _, _)] = comps.as_slice() {
            let selected = specs.get(*ci)?;
            (
                (self.size.0 * selected.h).div_ceil(8 * self.sampling.0),
                (self.size.1 * selected.v).div_ceil(8 * self.sampling.1),
            )
        } else {
            self.mcu
        };
        let mut bits = Entropy::new(data);
        let mut predictors = [0i32; 3];
        let mut eob = 0usize;
        let mut marker = 0u8;
        for y in 0..grid.1 {
            for x in 0..grid.0 {
                let mcu = y * grid.0 + x;
                if restart != 0 && mcu > 0 && mcu % restart == 0 {
                    if eob != 0 {
                        return None;
                    }
                    bits.restart(marker)?;
                    marker = (marker + 1) % 8;
                    predictors.fill(0);
                }
                for &(ci, td, ta) in &comps {
                    let spec = specs.get(ci)?;
                    let comp = self.components.get_mut(ci)?;
                    let (h, v) = if n == 1 { (1, 1) } else { (spec.h, spec.v) };
                    for by in y * v..(y + 1) * v {
                        for bx in x * h..(x + 1) * h {
                            if bx >= comp.stride || by >= comp.rows {
                                return None;
                            }
                            let block = comp.blocks.get_mut(by * comp.stride + bx)?;
                            if start == 0 {
                                if before == 0 {
                                    let table = dc.get(td)?.as_ref()?;
                                    let magnitude = bits.symbol(table)?;
                                    if magnitude > 11 {
                                        return None;
                                    }
                                    let pred = predictors.get_mut(ci)?;
                                    *pred = pred.checked_add(bits.signed(magnitude)?)?;
                                    block[0] = i16::try_from(pred.checked_mul(1 << after)?).ok()?;
                                } else if bits.bit()? != 0 {
                                    block[0] |= 1_i16 << after;
                                }
                            } else {
                                let coefficients = block.get_mut(start..=end)?;
                                let table = ac.get(ta)?.as_ref()?;
                                if before == 0 {
                                    first_ac(coefficients, table, &mut bits, &mut eob, after)?;
                                } else {
                                    refine_ac(
                                        coefficients,
                                        table,
                                        &mut bits,
                                        &mut eob,
                                        1_i16 << after,
                                    )?;
                                }
                            }
                        }
                    }
                }
            }
        }
        if eob != 0 || data.get(bits.pos) != Some(&0xff) {
            return None;
        }
        Some(bits.pos)
    }

    pub(super) fn finish(
        self,
        specs: &[Component],
        qtables: &[[u16; 64]; 4],
        model: bool,
    ) -> Option<DecodedImage> {
        let mut planes = Vec::with_capacity(specs.len());
        for (comp, spec) in self.components.into_iter().zip(specs) {
            if comp.successive[0].is_none() {
                return None;
            }
            let q = qtables.get(spec.tq)?;
            if q.contains(&0) {
                return None;
            }
            let w = comp.stride.checked_mul(8)?;
            let h = comp.rows.checked_mul(8)?;
            let mut pixels = vec![0u8; w.checked_mul(h)?];
            for (i, coefficients) in comp.blocks.into_iter().enumerate() {
                let mut block = [0; 64];
                for ((value, quant), position) in coefficients.into_iter().zip(q).zip(ZIGZAG) {
                    block[position] = i32::from(value) * i32::from(*quant);
                }
                idct_block(&mut block, model);
                let x = (i % comp.stride) * 8;
                let y = (i / comp.stride) * 8;
                for j in 0..8 {
                    let from = (y + j) * w + x;
                    for (out, value) in pixels
                        .get_mut(from..from + 8)?
                        .iter_mut()
                        .zip(&block[j * 8..j * 8 + 8])
                    {
                        *out = value.saturating_add(128).clamp(0, 255) as u8;
                    }
                }
            }
            planes.push(Plane { w, h, data: pixels });
        }
        planes_to_image(
            self.size.0,
            self.size.1,
            self.sampling.0,
            self.sampling.1,
            specs,
            &planes,
            model,
        )
    }
}

fn first_ac(
    band: &mut [i16],
    table: &HuffTable,
    bits: &mut Entropy<'_>,
    eob: &mut usize,
    low: u8,
) -> Option<()> {
    if *eob > 0 {
        *eob -= 1;
        return Some(());
    }
    let mut at = 0usize;
    while at < band.len() {
        let symbol = bits.symbol(table)?;
        let zeros = usize::from(symbol >> 4);
        let magnitude = symbol & 15;
        if magnitude == 0 {
            if zeros == 15 {
                at += 16;
                if at > band.len() {
                    return None;
                }
                continue;
            }
            *eob = (1 << zeros) + bits.bits(zeros)? - 1;
            break;
        }
        if magnitude > 10 {
            return None;
        }
        at += zeros;
        *band.get_mut(at)? = i16::try_from(bits.signed(magnitude)?.checked_mul(1 << low)?).ok()?;
        at += 1;
    }
    Some(())
}

fn refine(value: &mut i16, bits: &mut Entropy<'_>, step: i16) -> Option<()> {
    if bits.bit()? != 0 && *value & step == 0 {
        *value = if *value > 0 {
            value.checked_add(step)?
        } else {
            value.checked_sub(step)?
        };
    }
    Some(())
}

fn refine_ac(
    band: &mut [i16],
    table: &HuffTable,
    bits: &mut Entropy<'_>,
    eob: &mut usize,
    step: i16,
) -> Option<()> {
    let mut at = 0usize;
    if *eob == 0 {
        while at < band.len() {
            let symbol = bits.symbol(table)?;
            let mut zeros = usize::from(symbol >> 4);
            let incoming = match symbol & 15 {
                1 => Some(if bits.bit()? == 0 { -step } else { step }),
                0 if zeros == 15 => {
                    zeros += 1;
                    None
                }
                0 => {
                    *eob = (1 << zeros) + bits.bits(zeros)?;
                    break;
                }
                _ => return None,
            };
            while let Some(coefficient) = band.get_mut(at) {
                if *coefficient != 0 {
                    refine(coefficient, bits, step)?;
                } else if zeros > 0 {
                    zeros -= 1;
                    if zeros == 0 && incoming.is_none() {
                        at += 1;
                        break;
                    }
                } else {
                    break;
                }
                at += 1;
            }
            if zeros != 0 {
                return None;
            }
            if let Some(incoming) = incoming {
                *band.get_mut(at)? = incoming;
                at += 1;
            }
        }
    }
    if *eob > 0 {
        for coefficient in band.get_mut(at..)? {
            if *coefficient != 0 {
                refine(coefficient, bits, step)?;
            }
        }
        *eob -= 1;
    }
    Some(())
}

struct Entropy<'a> {
    source: &'a [u8],
    pos: usize,
    byte: u8,
    remaining: u8,
}

impl<'a> Entropy<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            pos: 0,
            byte: 0,
            remaining: 0,
        }
    }

    fn bit(&mut self) -> Option<usize> {
        if self.remaining == 0 {
            let value = *self.source.get(self.pos)?;
            self.pos += if value == 0xff {
                if self.source.get(self.pos + 1) != Some(&0) {
                    return None;
                }
                2
            } else {
                1
            };
            self.byte = value;
            self.remaining = 8;
        }
        self.remaining -= 1;
        Some(usize::from((self.byte >> self.remaining) & 1))
    }

    fn bits(&mut self, n: usize) -> Option<usize> {
        (0..n).try_fold(0, |value, _| Some(value << 1 | self.bit()?))
    }

    fn signed(&mut self, magnitude: u8) -> Option<i32> {
        if magnitude == 0 {
            return Some(0);
        }
        let value = i32::try_from(self.bits(usize::from(magnitude))?).ok()?;
        let base = 1 << magnitude;
        Some(if value < base / 2 {
            value + 1 - base
        } else {
            value
        })
    }

    fn symbol(&mut self, table: &HuffTable) -> Option<u8> {
        let mut code = 0_i32;
        for len in 1..=16 {
            code = code << 1 | self.bit()? as i32;
            let (min, max) = (*table.min_code.get(len)?, *table.max_code.get(len)?);
            if (min..=max).contains(&code) {
                let i = table
                    .val_ptr
                    .get(len)?
                    .checked_add(usize::try_from(code - min).ok()?)?;
                return table.symbols.get(i).copied();
            }
        }
        None
    }

    fn restart(&mut self, marker: u8) -> Option<()> {
        self.remaining = 0;
        if self.source.get(self.pos) != Some(&0xff) {
            return None;
        }
        while self.source.get(self.pos) == Some(&0xff) {
            self.pos += 1;
        }
        if self.source.get(self.pos) != Some(&(0xd0 + marker)) {
            return None;
        }
        self.pos += 1;
        Some(())
    }
}
