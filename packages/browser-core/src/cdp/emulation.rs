//! The Emulation domain: viewport, locale, geolocation and media overrides.

use super::{CdpBrowser, CdpCommand, CdpError, CdpHost, JsonValue, invalid, method_not_found};

impl CdpBrowser {
    pub(super) fn emulation_command(
        &mut self,
        cmd: &CdpCommand,
        host: &mut dyn CdpHost,
    ) -> Result<JsonValue, CdpError> {
        match cmd.method.as_str() {
            "Emulation.setDeviceMetricsOverride" => {
                let width = cmd
                    .params
                    .get("width")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(1280.0);
                let height = cmd
                    .params
                    .get("height")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(720.0);
                let session = self.session_for(cmd)?;
                session.viewport_width = (width as f32).clamp(320.0, 3840.0);
                session.viewport_height = (height as f32).clamp(240.0, 4320.0);
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.clearDeviceMetricsOverride" => {
                let session = self.session_for(cmd)?;
                session.viewport_width = 1280.0;
                session.viewport_height = 720.0;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setScriptExecutionDisabled" => {
                let disabled = cmd
                    .params
                    .get("value")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or(false);
                let session = self.session_for(cmd)?;
                session.js_enabled = !disabled;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setEmulatedMedia" => {
                let media = cmd
                    .params
                    .get("media")
                    .and_then(JsonValue::as_str)
                    .filter(|m| !m.is_empty())
                    .map(str::to_string);
                let session = self.session_for(cmd)?;
                session.emulated_media = media;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setGeolocationOverride" => {
                let lat = cmd.params.get("latitude").and_then(JsonValue::as_f64);
                let lon = cmd.params.get("longitude").and_then(JsonValue::as_f64);
                let acc = cmd
                    .params
                    .get("accuracy")
                    .and_then(JsonValue::as_f64)
                    .unwrap_or(1.0);
                {
                    let session = self.session_for(cmd)?;
                    // Omitting the coordinates emulates an unavailable position.
                    session.geolocation = match (lat, lon) {
                        (Some(a), Some(b)) => Some((a, b, acc)),
                        _ => None,
                    };
                }
                self.seed_realm(cmd, host)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.clearGeolocationOverride" => {
                {
                    let session = self.session_for(cmd)?;
                    session.geolocation = None;
                }
                self.seed_realm(cmd, host)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setTimezoneOverride" => {
                let tz = cmd
                    .params
                    .get("timezoneId")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("timezoneId required"))?
                    .to_string();
                {
                    let session = self.session_for(cmd)?;
                    session.timezone = if tz.is_empty() { None } else { Some(tz) };
                }
                self.seed_realm(cmd, host)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setLocaleOverride" => {
                let locale = cmd
                    .params
                    .get("locale")
                    .and_then(JsonValue::as_str)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string);
                {
                    let session = self.session_for(cmd)?;
                    session.locale = locale;
                }
                self.seed_realm(cmd, host)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setTouchEmulationEnabled" => {
                let enabled = cmd
                    .params
                    .get("enabled")
                    .and_then(JsonValue::as_bool)
                    .ok_or_else(|| invalid("enabled required"))?;
                {
                    let session = self.session_for(cmd)?;
                    session.touch_enabled = enabled;
                }
                self.seed_realm(cmd, host)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setCPUThrottlingRate" => {
                let rate = cmd
                    .params
                    .get("rate")
                    .and_then(JsonValue::as_f64)
                    .ok_or_else(|| invalid("rate required"))?;
                // Written negated so a NaN rate is refused too.
                #[allow(clippy::neg_cmp_op_on_partial_ord)]
                if !(rate >= 1.0) {
                    return Err(invalid("rate must be >= 1"));
                }
                let session = self.session_for(cmd)?;
                session.cpu_throttle = rate;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setDefaultBackgroundColorOverride" => {
                let color = cmd.params.get("color").map(|c| {
                    let ch = |k: &str, d: f64| c.get(k).and_then(JsonValue::as_f64).unwrap_or(d);
                    (
                        ch("r", 255.0).clamp(0.0, 255.0) as u8,
                        ch("g", 255.0).clamp(0.0, 255.0) as u8,
                        ch("b", 255.0).clamp(0.0, 255.0) as u8,
                        (ch("a", 1.0).clamp(0.0, 1.0) * 255.0) as u8,
                    )
                });
                let session = self.session_for(cmd)?;
                session.background_override = color;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setEmulatedVisionDeficiency" => {
                let ty = cmd
                    .params
                    .get("type")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| invalid("type required"))?;
                if !matches!(
                    ty,
                    "none" | "blurredVision" | "reducedContrast" | "achromatopsia"
                        | "deuteranopia" | "protanopia" | "tritanopia"
                ) {
                    return Err(invalid("unknown vision deficiency type"));
                }
                self.session_for(cmd)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setIdleOverride" => {
                if cmd.params.get("isUserActive").and_then(JsonValue::as_bool).is_none()
                    || cmd
                        .params
                        .get("isScreenUnlocked")
                        .and_then(JsonValue::as_bool)
                        .is_none()
                {
                    return Err(invalid("isUserActive and isScreenUnlocked required"));
                }
                self.session_for(cmd)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.clearIdleOverride" | "Emulation.setEmulatedOSTextScale" => {
                self.session_for(cmd)?;
                Ok(JsonValue::obj(vec![]))
            }
            "Emulation.setUserAgentOverride" => self.network_command(cmd, host),
            other => Err(method_not_found(other)),
        }
    }
}
