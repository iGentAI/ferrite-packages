/*!
 * Rsx client runtime v1.
 *
 * Instant navigation over the page-payload wire (wire-v1 §2): links are
 * intercepted, the payload is fetched, and only the segments that
 * actually changed are patched into the DOM. Everything else — the
 * layout chrome, a playing <audio>, an open <dialog>, scroll position
 * inside a persistent pane — survives, because it is never re-created.
 *
 * Dependency-free by construction. No build step: this file IS the
 * asset, embedded in the application binary and served from a
 * content-addressed URL.
 *
 * Degradation is the design: with JavaScript off, or if anything here
 * throws, every link is still an ordinary link to a complete document.
 */
(function () {
  "use strict";

  if (window.__rsx && window.__rsx.ready) return;

  var doc = document;
  var STATE_SELECTOR = 'script[type="application/rsx-state"]';
  var CACHE_MAX = 32;
  var PREFETCH_MAX_INFLIGHT = 3;
  var DEFAULT_STALE_MS = 30000;

  /** url -> { payload, etag, staleAt, tags } */
  var cache = new Map();
  /** segment id -> hash, for the document currently on screen */
  var have = new Map();
  /** url -> in-flight promise (one request per URL, never a stampede) */
  var inflight = new Map();
  var islands = (window.__rsx && window.__rsx.islands) || {};
  /** island name -> module URL, from the document's boot state. */
  var islandSources = {};
  var prefetching = 0;
  var navToken = 0;
  var announcer = null;

  // ---------------------------------------------------------------
  // environment
  // ---------------------------------------------------------------

  function reducedMotion() {
    return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }

  function frugal() {
    var c = navigator.connection;
    return !!(c && (c.saveData || /(^|-)2g$/.test(c.effectiveType || "")));
  }

  function sameOrigin(href) {
    try {
      var u = new URL(href, location.href);
      return u.origin === location.origin ? u : null;
    } catch (e) {
      return null;
    }
  }

  /** A path inside this application: the server's `is_local_path` rule. */
  function isLocalPath(target) {
    return (
      typeof target === "string" &&
      target.charAt(0) === "/" &&
      target.charAt(1) !== "/" &&
      target.charAt(1) !== "\\" &&
      !/[\u0000-\u001f\u007f]/.test(target)
    );
  }

  /** The absolute http(s) URL a full navigation may go to, or null. */
  function navigableUrl(href) {
    try {
      var u = new URL(href, location.href);
      return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
    } catch (e) {
      return null;
    }
  }

  // ---------------------------------------------------------------
  // segment state
  // ---------------------------------------------------------------

  function readState() {
    have.clear();
    var el = doc.querySelector(STATE_SELECTOR);
    if (!el) return null;
    try {
      var state = JSON.parse(el.textContent || "{}");
      (state.segments || []).forEach(function (s) {
        if (s && s.id && s.hash) have.set(s.id, s.hash);
      });
      // The island manifest is per BUILD, not per page, so reading it
      // once at boot is enough — and it is what lets a marker's module
      // be fetched only when a marker actually appears.
      if (state.islands) islandSources = state.islands;
      return state;
    } catch (e) {
      return null;
    }
  }

  function haveHeader() {
    var parts = [];
    have.forEach(function (hash, id) {
      parts.push(id + "=" + hash);
    });
    return parts.join(",");
  }

  /**
   * The CONTENTS of a layout's slot, as a Range.
   *
   * The markers themselves stay put, so the anchor survives every
   * navigation: a slot exists for as long as its layout does, which is
   * exactly why the protocol patches slots and not pages.
   */
  function slotRange(id) {
    var walker = doc.createTreeWalker(doc.documentElement, NodeFilter.SHOW_COMMENT, null);
    var open = "aly:h:" + id;
    var close = "aly:/h:" + id;
    var start = null;
    var node;
    while ((node = walker.nextNode())) {
      if (node.data === open) start = node;
      else if (node.data === close && start) {
        var range = doc.createRange();
        range.setStartAfter(start);
        range.setEndBefore(node);
        return range;
      }
    }
    return null;
  }

  /**
   * Replace a slot's contents, carrying live "permanent" elements
   * across untouched.
   *
   * A permanent element is identified by id and MOVED into the incoming
   * fragment before the old contents are deleted, so the node the
   * browser is playing audio from (or typing into) is literally the
   * same node afterwards — not a re-created copy that would restart it.
   */
  function applyPatch(id, html) {
    var range = slotRange(id);
    if (!range) return false;

    var live = [];
    doc.querySelectorAll("[data-rsx-permanent][id]").forEach(function (el) {
      try {
        if (range.intersectsNode(el)) live.push(el);
      } catch (e) {
        /* older engines: skip preservation rather than fail the nav */
      }
    });

    var fragment;
    try {
      fragment = range.createContextualFragment(html);
    } catch (e) {
      return false;
    }

    live.forEach(function (node) {
      var slot = fragment.querySelector('[data-rsx-permanent][id="' + cssEscape(node.id) + '"]');
      if (slot && slot.parentNode) slot.parentNode.replaceChild(node, slot);
    });

    range.deleteContents();
    range.insertNode(fragment);
    return true;
  }

  function cssEscape(value) {
    if (window.CSS && CSS.escape) return CSS.escape(value);
    return String(value).replace(/[^a-zA-Z0-9_-]/g, function (c) {
      return "\\" + c;
    });
  }

  // ---------------------------------------------------------------
  // payload fetching and caching
  // ---------------------------------------------------------------

  function staleOf(res) {
    var raw = parseInt(res.headers.get("x-rsx-stale") || "", 10);
    return isNaN(raw) ? DEFAULT_STALE_MS : raw;
  }

  function remember(url, payload, res, basis) {
    var tags = (res && res.headers.get("x-rsx-tags")) || (payload.tags || []).join(",");
    cache.set(url, {
      payload: payload,
      // The segment state this payload was DIFFERENCED against. "" means
      // complete (every segment carries html), so it can be applied from
      // any page; anything else may only be reused from that exact
      // state, because its `html: null` entries mean "you already have
      // this" — a claim that is false from a different page.
      basis: basis || "",
      etag: res ? res.headers.get("etag") : null,
      staleAt: Date.now() + (res ? staleOf(res) : payload.stale_ms || DEFAULT_STALE_MS),
      tags: tags ? tags.split(",").filter(Boolean) : []
    });
    while (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
  }

  function usable(entry) {
    if (!entry || entry.staleAt <= Date.now()) return false;
    // A payload is a patch against the state it was requested from;
    // applying it from anywhere else would patch the wrong slot.
    return entry.basis === haveHeader();
  }

  function fetchPayload(url, opts) {
    opts = opts || {};
    var requestedTarget = sameOrigin(url);
    if (!requestedTarget) {
      return Promise.reject(new Error("rsx: cross-origin payload"));
    }
    var entry = cache.get(url);
    if (!opts.force && usable(entry)) {
      return Promise.resolve(entry.payload);
    }
    // EVERY request states the segments this client currently has, so
    // the answer is a patch against a known basis. The basis is stored
    // with the payload, and a cached answer is only reused from that
    // same basis — which is what makes prefetching safe.
    var basis = haveHeader();
    var key = url + "\u0000" + basis;
    if (inflight.has(key)) return inflight.get(key);

    var headers = { "x-rsx-nav": "1" };
    if (basis) headers["x-rsx-have"] = basis;
    if (opts.prefetch) headers["x-rsx-prefetch"] = "1";
    if (entry && entry.etag && entry.basis === basis) headers["if-none-match"] = entry.etag;

    var request = fetch(url, {
      headers: headers,
      credentials: "same-origin",
      redirect: "follow"
    })
      .then(function (res) {
        var finalTarget = res.url
          ? sameOrigin(res.url)
          : res.redirected
          ? null
          : requestedTarget;
        if (!finalTarget) {
          var xorigin = new Error("rsx: cross-origin redirect");
          xorigin.redirectUrl = res.url || null;
          throw xorigin;
        }
        var finalHref = res.url
          ? finalTarget.pathname +
            finalTarget.search +
            (finalTarget.hash || requestedTarget.hash || "")
          : url;
        if (res.status === 304 && entry && entry.basis === basis) {
          entry.staleAt = Date.now() + staleOf(res);
          return entry.payload;
        }
        if (!res.ok) throw new Error("rsx: HTTP " + res.status);
        var type = res.headers.get("content-type") || "";
        if (type.indexOf("application/json") === -1) {
          // The server answered a document: this route is not
          // soft-navigable (a redirect to a foreign page, say).
          throw new Error("rsx: not a payload");
        }
        return res.json().then(function (payload) {
          if (payload && typeof payload === "object") {
            try {
              Object.defineProperty(payload, "__rsxUrl", {
                value: finalHref,
                configurable: true
              });
            } catch (e) {}
          }
          remember(finalHref, payload, res, basis);
          return payload;
        });
      });

    inflight.set(key, request);
    var settle = function () {
      inflight.delete(key);
    };
    request.then(settle, settle);
    return request;
  }

  // ---------------------------------------------------------------
  // navigation
  // ---------------------------------------------------------------

  function hardNavigate(url) {
    var target = navigableUrl(url);
    if (!target) {
      if (window.console) console.warn("rsx: refused to navigate to a non-http(s) URL");
      return false;
    }
    location.href = target;
    return true;
  }

  /**
   * Whether this payload can be applied to the document on screen.
   *
   * `patch_at: null` means the server found no layout in common — there
   * is nothing to patch, so the navigation is an ordinary page load.
   * `html: null` means the render is identical to what is already
   * shown, which is a valid outcome with no DOM work at all.
   */
  function canApply(payload) {
    if (!payload || !payload.patch_at) return false;
    if (payload.html === null || payload.html === undefined) return true;
    return !!slotRange(payload.patch_at);
  }

  function applyPayload(payload) {
    if (payload.html !== null && payload.html !== undefined) {
      if (!applyPatch(payload.patch_at, payload.html)) return false;
    }
    have.clear();
    (payload.segments || []).forEach(function (s) {
      if (s && s.id && s.hash) have.set(s.id, s.hash);
    });
    if (payload.head && typeof payload.head.title === "string") {
      doc.title = payload.head.title;
    }
    return true;
  }

  function withTransition(apply, kind) {
    if (!doc.startViewTransition || reducedMotion()) {
      apply();
      return Promise.resolve();
    }
    var root = doc.documentElement;
    if (kind) root.setAttribute("data-rsx-transition", kind);
    markTransitionNames();
    var transition = doc.startViewTransition(apply);
    return transition.finished
      .catch(function () {})
      .then(function () {
        root.removeAttribute("data-rsx-transition");
      });
  }

  /** `transition:name` in a template becomes a real morph pair here. */
  function markTransitionNames() {
    doc.querySelectorAll("[data-rsx-transition-name]").forEach(function (el) {
      el.style.viewTransitionName = el.getAttribute("data-rsx-transition-name");
    });
  }

  function navigate(url, opts) {
    opts = opts || {};
    var target = sameOrigin(url);
    if (!target) {
      hardNavigate(url);
      return Promise.resolve();
    }
    var href = target.pathname + target.search + target.hash;
    var token = ++navToken;
    var root = doc.documentElement;
    root.setAttribute("data-rsx-navigating", "");

    if (opts.push !== false) {
      // Record where THIS page was before leaving it, so Back restores
      // the scroll position the user actually left.
      try {
        history.replaceState(
          Object.assign({}, history.state || {}, { rsx: 1, scroll: window.scrollY }),
          ""
        );
      } catch (e) {}
    }

    var commit = function (payload) {
      var resolvedTarget =
        (payload && payload.__rsxUrl && sameOrigin(payload.__rsxUrl)) || target;
      var resolvedHref =
        resolvedTarget.pathname + resolvedTarget.search + resolvedTarget.hash;
      return withTransition(function () {
        if (!applyPayload(payload)) {
          hardNavigate(resolvedHref);
          return;
        }
        if (opts.push !== false) {
          history.pushState({ rsx: 1, scroll: 0 }, "", resolvedHref);
        }
        settle(resolvedTarget, opts);
      }, opts.transition);
    };

    return fetchPayload(href, { force: opts.force })
      .then(function (payload) {
        if (token !== navToken) return; // superseded by a later click
        if (canApply(payload)) return commit(payload);
        // A cached payload built against a different page state, or a
        // race with another navigation. Ask again from the CURRENT
        // basis before falling back to a full page load.
        return fetchPayload(href, { force: true }).then(function (fresh) {
          if (token !== navToken) return;
          if (canApply(fresh)) return commit(fresh);
          hardNavigate((fresh && fresh.__rsxUrl) || href);
        });
      })
      .catch(function (err) {
        if (token === navToken) hardNavigate((err && err.redirectUrl) || href);
      })
      .then(function () {
        root.removeAttribute("data-rsx-navigating");
      });
  }

  /** Scroll, focus, announcement, hydration, observation. */
  function settle(target, opts) {
    if (opts.preserve) {
      // A HOT REFRESH (a dev rebuild, or a mutation's own re-render) is
      // not a navigation: the reader did not ask to go anywhere. Moving
      // the scroll position, stealing focus or announcing a route change
      // would all be wrong, so only the parts that MUST run after new
      // DOM arrives do — including closing the live subscriptions whose
      // regions the patch detached, before opening the new ones.
      hydrateIslands();
      fillSlots();
      closeDetachedLive();
      sweepWatchers();
      openLiveRegions();
      observeLinks();
      doc.dispatchEvent(new CustomEvent("rsx:refreshed", { detail: { url: location.pathname } }));
      return;
    }
    if (target.hash) {
      var anchor = doc.getElementById(target.hash.slice(1));
      if (anchor) anchor.scrollIntoView();
    } else if (opts.scroll !== false) {
      window.scrollTo(0, opts.scrollTo || 0);
    }

    // Focus moves to the new content, or a screen-reader user would
    // still be inside the old page's landmark with no idea anything
    // happened.
    var focusTarget =
      doc.querySelector("[data-rsx-focus]") || doc.querySelector("main") || doc.body;
    if (focusTarget && focusTarget !== doc.body) {
      if (!focusTarget.hasAttribute("tabindex")) focusTarget.setAttribute("tabindex", "-1");
      try {
        focusTarget.focus({ preventScroll: true });
      } catch (e) {
        focusTarget.focus();
      }
    }
    announce(doc.title);
    hydrateIslands();
    fillSlots();
    closeDetachedLive();
    sweepWatchers();
    openLiveRegions();
    observeLinks();
    doc.dispatchEvent(new CustomEvent("rsx:navigated", { detail: { url: location.pathname } }));
  }

  function announce(text) {
    if (!announcer) {
      announcer = doc.createElement("div");
      announcer.setAttribute("aria-live", "polite");
      announcer.setAttribute("aria-atomic", "true");
      announcer.style.cssText =
        "position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;" +
        "clip:rect(0 0 0 0);white-space:nowrap;border:0";
      doc.body.appendChild(announcer);
    }
    announcer.textContent = "";
    // A same-value write is not an announcement; the tick forces one.
    setTimeout(function () {
      announcer.textContent = text || "";
    }, 30);
  }

  // ---------------------------------------------------------------
  // links: interception and prefetch
  // ---------------------------------------------------------------

  function navigableLink(el) {
    var a = el.closest ? el.closest("a[href]") : null;
    if (!a) return null;
    if (a.hasAttribute("download") || a.hasAttribute("data-rsx-no-nav")) return null;
    if (a.target && a.target !== "_self") return null;
    if ((a.getAttribute("rel") || "").indexOf("external") !== -1) return null;
    return sameOrigin(a.getAttribute("href")) ? a : null;
  }

  function onClick(event) {
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    var a = navigableLink(event.target);
    if (!a) return;
    var url = sameOrigin(a.getAttribute("href"));
    if (!url) return;
    // An in-page anchor is the browser's job, not ours.
    if (url.pathname === location.pathname && url.search === location.search && url.hash) return;
    event.preventDefault();
    navigate(url.href, { transition: a.getAttribute("data-rsx-transition-type") || null });
  }

  function prefetch(url, reason) {
    if (frugal()) return;
    if (prefetching >= PREFETCH_MAX_INFLIGHT) return;
    if (usable(cache.get(url))) return;
    prefetching++;
    var done = function () {
      prefetching--;
    };
    // A prefetch is a patch against the CURRENT page state, cached with
    // that basis: clicking the link from this page reuses it, and
    // navigating away first simply invalidates it. `reason` only records
    // why it was warmed.
    fetchPayload(url, { prefetch: true, reason: reason }).then(done, done);
  }

  function linkUrl(a) {
    var u = sameOrigin(a.getAttribute("href"));
    return u ? u.pathname + u.search : null;
  }

  var viewportObserver =
    "IntersectionObserver" in window
      ? new IntersectionObserver(
          function (entries) {
            entries.forEach(function (entry) {
              if (!entry.isIntersecting) return;
              var url = linkUrl(entry.target);
              if (url) prefetch(url, "viewport");
              viewportObserver.unobserve(entry.target);
            });
          },
          { rootMargin: "200px" }
        )
      : null;

  function observeLinks() {
    if (!viewportObserver) return;
    doc.querySelectorAll("a[href]").forEach(function (a) {
      if (a.__rsxSeen) return;
      if (!navigableLink(a)) return;
      if (a.getAttribute("data-rsx-prefetch") === "false") return;
      a.__rsxSeen = true;
      viewportObserver.observe(a);
    });
  }

  function onIntent(event) {
    var a = navigableLink(event.target);
    if (!a) return;
    var url = linkUrl(a);
    if (url) prefetch(url, "intent");
  }

  // ---------------------------------------------------------------
  // islands
  // ---------------------------------------------------------------

  var islandObserver =
    "IntersectionObserver" in window
      ? new IntersectionObserver(function (entries) {
          entries.forEach(function (entry) {
            if (!entry.isIntersecting) return;
            islandObserver.unobserve(entry.target);
            hydrate(entry.target);
          });
        })
      : null;

  function hydrate(el) {
    if (el.__rsxHydrated) return;
    var name = el.getAttribute("data-rsx-island");
    var factory = islands[name];
    if (!factory) {
      // The module has not registered yet. Fetch it — once per island,
      // and only because a marker for it is on this page. The module
      // calls __rsx.island(name, factory), which re-runs hydration.
      loadIsland(name);
      return;
    }
    el.__rsxHydrated = true;
    var props = {};
    try {
      props = JSON.parse(el.getAttribute("data-rsx-props") || "{}");
    } catch (e) {}
    try {
      factory(el, props);
    } catch (e) {
      el.__rsxHydrated = false;
      if (window.console) console.error("rsx island '" + name + "' failed", e);
    }
  }

  /** Modules already requested, so a page of markers fetches one each. */
  var islandLoads = {};

  function loadIsland(name) {
    var src = islandSources[name];
    if (!src || islandLoads[name]) return;
    islandLoads[name] = true;
    import(src)
      .then(function (mod) {
        // Two conventions, both supported: a module that calls
        // `__rsx.island(name, factory)` has already registered (and
        // re-run hydration), and one that simply default-exports a
        // factory is registered here. Without this second case a
        // perfectly ordinary ES module would load and do nothing.
        if (!islands[name] && mod && typeof mod.default === "function") {
          islands[name] = mod.default;
        }
        hydrateIslands();
      })
      .catch(function (e) {
        // Let a later navigation try again rather than wedging the
        // island for the life of the page.
        islandLoads[name] = false;
        if (window.console) console.error("rsx could not load island '" + name + "'", e);
      });
  }

  function hydrateIslands(root) {
    (root || doc).querySelectorAll("[data-rsx-island]").forEach(function (el) {
      if (el.__rsxHydrated) return;
      var how = el.getAttribute("data-rsx-hydrate") || "load";
      if (how === "visible" && islandObserver) {
        islandObserver.observe(el);
        return;
      }
      if (how === "idle" && window.requestIdleCallback) {
        requestIdleCallback(function () {
          hydrate(el);
        });
        return;
      }
      hydrate(el);
    });
  }

  // ---------------------------------------------------------------
  // deferred slots
  // ---------------------------------------------------------------

  /**
   * Fill the holes a shell left behind.
   *
   * A DOCUMENT arrives complete — every boundary resolved — so this is
   * a no-op on first load, which is what keeps the first paint, a bot
   * and a reader without JavaScript all correct. Only a soft
   * navigation defers, and only then is there anything to fetch.
   */
  function fillSlots() {
    var pending = doc.querySelectorAll("[data-rsx-slot][data-rsx-slot-pending]");
    if (!pending.length) return;
    var path = location.pathname + location.search;
    pending.forEach(function (el) {
      var id = el.getAttribute("data-rsx-slot");
      if (!id) return;
      // Claimed immediately, so a second pass cannot fetch it twice.
      el.removeAttribute("data-rsx-slot-pending");
      fetch(
        "/_rsx/slot/" + encodeURIComponent(id) + "?path=" + encodeURIComponent(path),
        { credentials: "same-origin" }
      )
        .then(function (res) {
          var slotTarget = res.url
            ? sameOrigin(res.url)
            : res.redirected
            ? null
            : location;
          if (!slotTarget) throw new Error("rsx: cross-origin slot redirect");
          if (!res.ok) throw new Error("rsx: slot " + res.status);
          var slotType = res.headers.get("content-type") || "";
          if (slotType.indexOf("application/json") === -1) {
            throw new Error("rsx: slot not json");
          }
          return res.json();
        })
        .then(function (payload) {
          if (!payload || typeof payload.html !== "string") return;
          // A navigation may have replaced this hole while the request
          // was in flight; filling a detached node would be invisible
          // work at best and a leak at worst.
          if (!el.isConnected) return;
          var range = doc.createRange();
          range.selectNodeContents(el);
          range.deleteContents();
          el.appendChild(range.createContextualFragment(payload.html));
          el.setAttribute("data-rsx-slot-filled", "");
          hydrateIslands(el);
          // A resolved boundary can contain a live region, and this
          // fetch finishes AFTER settle() scanned the page — so the
          // new content is scanned here or its region never subscribes.
          openLiveRegions(el);
          el.dispatchEvent(new CustomEvent("rsx:slot", { bubbles: true, detail: { id: id } }));
        })
        .catch(function () {
          // The fallback stays on screen, marked, rather than the hole
          // silently pretending to be content.
          if (el.isConnected) el.setAttribute("data-rsx-slot-failed", "");
        });
    });
  }

  // ---------------------------------------------------------------
  // live regions
  // ---------------------------------------------------------------

  /** Regions with an open subscription, so detached ones can be closed. */
  var liveRegions = [];

  /**
   * Subscribe one region.
   *
   * The cursor is read from the DOM at CONNECT time, and advanced as
   * frames arrive, so a reconnect resumes exactly where this region got
   * to — not where the page was rendered. That is the whole point of a
   * log offset: no replay, no client-side deduplication.
   */
  function openLive(el) {
    if (el.__rsxLive || !window.EventSource) return;
    // A detached region is one a navigation already replaced: opening a
    // connection for it would be permanently invisible work, and
    // closeDetachedLive has no way to find it again.
    if (!el.isConnected) return;
    var source = el.getAttribute("data-rsx-live");
    if (!source) return;
    var from = el.getAttribute("data-rsx-from") || "0";
    var url =
      "/_live/subscribe?source=" + encodeURIComponent(source) + "&from=" + encodeURIComponent(from);
    var es = new EventSource(url);
    el.__rsxLive = es;
    if (liveRegions.indexOf(el) === -1) liveRegions.push(el);

    var stop = function () {
      es.close();
      el.__rsxLive = null;
    };

    es.addEventListener("live", function (event) {
      var payload;
      try {
        payload = JSON.parse(event.data);
      } catch (e) {
        return;
      }
      // A refusal ENDS the subscription and says so in the DOM: a
      // region that will never receive anything must not look like one
      // that is merely quiet.
      if (payload.refused) {
        el.setAttribute("data-rsx-live-refused", payload.refused);
        stop();
        return;
      }
      if (typeof payload.html !== "string") return;
      // A navigation may have replaced this region while the frame was
      // in flight; writing into a detached node is invisible work.
      if (!el.isConnected) {
        stop();
        return;
      }
      el.insertAdjacentHTML("beforeend", payload.html);
      el.setAttribute("data-rsx-from", String((payload.offset || 0) + 1));
      el.dispatchEvent(
        new CustomEvent("rsx:live", {
          bubbles: true,
          detail: { source: source, offset: payload.offset }
        })
      );
    });

    es.onerror = function () {
      stop();
      if (!el.isConnected) return;
      // Reconnect and resume from the cursor above. EventSource would
      // retry the ORIGINAL url by itself, which would replay from the
      // offset the page was rendered at — so the retry is ours. The
      // check is repeated INSIDE the timer because a navigation can
      // detach this region while it is pending.
      setTimeout(function () {
        if (el.isConnected) openLive(el);
      }, 1000);
    };
  }

  function openLiveRegions(root) {
    (root || doc).querySelectorAll("[data-rsx-live]").forEach(openLive);
  }

  /** Close the subscriptions of regions a navigation removed. */
  function closeDetachedLive() {
    liveRegions = liveRegions.filter(function (el) {
      if (el.isConnected) return true;
      if (el.__rsxLive) {
        el.__rsxLive.close();
        el.__rsxLive = null;
      }
      return false;
    });
  }

  // ---------------------------------------------------------------
  // optimistic updates
  // ---------------------------------------------------------------

  /**
   * Parse an optimistic spec into operations.
   *
   * `"toggle-class:starred; text:Saved@.label"` — operations separated
   * by `;`, each `op[:arg][@selector]`, where the selector picks the
   * element to change (default: the form itself). Kept as a pure
   * function so the grammar can be reasoned about, and exposed on the
   * public surface so a page can check what it declared.
   */
  function parseOptimistic(spec) {
    return String(spec || "")
      .split(";")
      .map(function (part) { return part.trim(); })
      .filter(Boolean)
      .map(function (part) {
        var target = null;
        var at = part.lastIndexOf("@");
        if (at !== -1) {
          target = part.slice(at + 1).trim() || null;
          part = part.slice(0, at).trim();
        }
        var colon = part.indexOf(":");
        var op = (colon === -1 ? part : part.slice(0, colon)).trim();
        var arg = colon === -1 ? "" : part.slice(colon + 1).trim();
        return { op: op, arg: arg, target: target };
      })
      .filter(function (op) { return op.op.length > 0; });
  }

  /**
   * Resolve an operation's target without throwing.
   *
   * `querySelector` THROWS on an invalid selector, and this runs before
   * the request is sent — an exception here would suppress the mutation
   * and leave the form marked pending forever. A bad selector simply
   * finds nothing instead.
   */
  function safeQuery(root, selector) {
    try {
      return root.querySelector(selector) || doc.querySelector(selector);
    } catch (e) {
      return null;
    }
  }

  /** A usable class token: `classList` throws on empty or spaced input. */
  function isClassToken(value) {
    return typeof value === "string" && value.length > 0 && !/\s/.test(value);
  }

  /**
   * Apply an optimistic update, returning the function that UNDOES it.
   *
   * Every operation records the prior state before changing anything,
   * so a rollback restores exactly what was there — not an assumed
   * default. Every operation is also INDIVIDUALLY guarded: a typo in a
   * decoration must never stop the mutation it decorates, and because
   * this runs after the form is marked pending, a thrown error would
   * wedge that form permanently.
   */
  function applyOptimistic(root, spec) {
    var undos = [];
    var ops = [];
    try {
      ops = parseOptimistic(spec);
    } catch (e) {
      ops = [];
    }
    ops.forEach(function (op) {
      try {
        var el = op.target ? safeQuery(root, op.target) : root;
        if (!el) return;
        switch (op.op) {
          case "add-class":
            if (isClassToken(op.arg) && !el.classList.contains(op.arg)) {
              el.classList.add(op.arg);
              undos.push(function () { el.classList.remove(op.arg); });
            }
            break;
          case "remove-class":
            if (isClassToken(op.arg) && el.classList.contains(op.arg)) {
              el.classList.remove(op.arg);
              undos.push(function () { el.classList.add(op.arg); });
            }
            break;
          case "toggle-class":
            if (isClassToken(op.arg)) {
              el.classList.toggle(op.arg);
              undos.push(function () { el.classList.toggle(op.arg); });
            }
            break;
          case "remove": {
            var previous = el.hidden;
            el.hidden = true;
            undos.push(function () { el.hidden = previous; });
            break;
          }
          case "text": {
            var before = el.textContent;
            el.textContent = op.arg;
            undos.push(function () { el.textContent = before; });
            break;
          }
          case "toggle-text": {
            var pair = op.arg.split("|");
            if (pair.length !== 2) break;
            var current = (el.textContent || "").trim();
            var next = current === pair[0].trim() ? pair[1] : pair[0];
            var original = el.textContent;
            el.textContent = next;
            undos.push(function () { el.textContent = original; });
            break;
          }
          default:
            // Unknown: deliberately nothing.
            break;
        }
      } catch (e) {
        if (window.console) {
          console.warn("rsx: an optimistic operation failed", op, e);
        }
      }
    });
    return function undo() {
      // In reverse, so composed operations unwind cleanly — and
      // guarded, because a rollback that throws would strand the
      // interface in the optimistic state it was meant to leave.
      for (var i = undos.length - 1; i >= 0; i--) {
        try {
          undos[i]();
        } catch (e) {
          if (window.console) console.warn("rsx: an optimistic undo failed", e);
        }
      }
    };
  }

  // ---------------------------------------------------------------
  // the offline outbox
  // ---------------------------------------------------------------

  /*
   * Mutations that could not be delivered, kept until they are.
   *
   * Safe for exactly one reason: a queued submission keeps its ORIGINAL
   * idempotency key, so replaying it is a DUPLICATE rather than a
   * second mutation — the server recognizes it and replays the answer
   * it already recorded. Minting a fresh key on reconnect would turn
   * one offline click into two effects, which is the failure this whole
   * design exists to prevent.
   *
   * IndexedDB when it is available, an in-memory list when it is not
   * (private browsing, a storage policy). The degradation is honest:
   * the queue then survives a reconnect but not a reload.
   *
   * Replay runs under the session held AT REPLAY, so an entry keeps the
   * identity of the press: the value of the cookie named by
   * `<meta name="rsx-outbox-scope-cookie">` (opaque, per identity, set
   * by the app). It replays automatically only while the cookie still
   * holds that value; another value discards it; otherwise it is held for
   * `__rsx.drain({ confirm: true })` (unscoped only) or
   * `__rsx.clearOutbox()` (call it at sign-out). Limits: OUTBOX_MAX_*.
   */
  var OUTBOX_DB = "__rsx";
  var OUTBOX_STORE = "outbox";
  var OUTBOX_KEY_PATH = "key";
  var OUTBOX_MAX_ATTEMPTS = 8;
  var OUTBOX_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
  var OUTBOX_MAX_ENTRIES = 50;
  var OUTBOX_SCOPE_SELECTOR = 'meta[name="rsx-outbox-scope-cookie"]';
  var pendingActions = [];
  var outboxDb = null;
  var outboxUnavailable = false;
  /** Bumped by a clear: work begun before it must not continue. */
  var outboxGeneration = 0;

  /** The reader identity now: the scope cookie's value, or "". */
  function outboxScope() {
    var el = doc.querySelector(OUTBOX_SCOPE_SELECTOR);
    var name = el && el.getAttribute("content");
    var found = "";
    if (name) {
      String(doc.cookie || "").split(";").forEach(function (part) {
        var at = part.indexOf("=");
        if (at > 0 && part.slice(0, at).trim() === name) found = part.slice(at + 1).trim();
      });
    }
    return found;
  }

  function openOutbox() {
    if (outboxUnavailable || !window.indexedDB) return Promise.resolve(null);
    if (outboxDb) return Promise.resolve(outboxDb);
    return new Promise(function (resolve) {
      var request;
      try {
        request = indexedDB.open(OUTBOX_DB, 1);
      } catch (e) {
        outboxUnavailable = true;
        resolve(null);
        return;
      }
      request.onupgradeneeded = function () {
        var db = request.result;
        if (!db.objectStoreNames.contains(OUTBOX_STORE)) {
          db.createObjectStore(OUTBOX_STORE, { keyPath: OUTBOX_KEY_PATH });
        }
      };
      request.onsuccess = function () {
        outboxDb = request.result;
        resolve(outboxDb);
      };
      request.onerror = function () {
        // One refusal is enough: fall back to memory rather than
        // retrying a storage layer the browser has denied.
        outboxUnavailable = true;
        resolve(null);
      };
    });
  }

  function outboxWrite(apply) {
    return openOutbox().then(function (db) {
      if (!db) return null;
      return new Promise(function (resolve) {
        var tx = db.transaction(OUTBOX_STORE, "readwrite");
        apply(tx.objectStore(OUTBOX_STORE));
        tx.oncomplete = function () { resolve(true); };
        tx.onerror = function () { resolve(null); };
      });
    });
  }

  function outboxRead() {
    return openOutbox().then(function (db) {
      if (!db) return pendingActions.slice();
      return new Promise(function (resolve) {
        var tx = db.transaction(OUTBOX_STORE, "readonly");
        var request = tx.objectStore(OUTBOX_STORE).getAll();
        tx.oncomplete = function () {
          var rows = request.result || [];
          rows.sort(function (a, b) { return (a.at || 0) - (b.at || 0); });
          pendingActions = rows.slice();
          resolve(rows);
        };
        tx.onerror = function () { resolve(pendingActions.slice()); };
      });
    });
  }

  // Named apart from the navigation cache's remember(): two function
  // declarations in one scope are one binding, and the later one won, so
  // every prefetch landed in pendingActions.
  function rememberOutbox(entry) {
    pendingActions = pendingActions.filter(function (e) { return e.key !== entry.key; });
    pendingActions.push(entry);
    announcePending();
  }

  /** Queue `entry` (bounded in the transaction, so across tabs), or with
   *  `update` rewrite it only if still queued. Resolves whether stored. */
  function outboxAdd(entry, update) {
    return openOutbox().then(function (db) {
      if (!db) {
        var present = pendingActions.some(function (e) { return e.key === entry.key; });
        if (!present && (update || pendingActions.length >= OUTBOX_MAX_ENTRIES)) return false;
        rememberOutbox(entry);
        return true;
      }
      return new Promise(function (resolve) {
        var stored = false;
        var tx = db.transaction(OUTBOX_STORE, "readwrite");
        var store = tx.objectStore(OUTBOX_STORE);
        var existing = store.get(entry.key);
        existing.onsuccess = function () {
          if (existing.result) {
            store.put(entry);
            stored = true;
          } else if (!update) {
            var count = store.count();
            count.onsuccess = function () {
              if (count.result < OUTBOX_MAX_ENTRIES) {
                store.put(entry);
                stored = true;
              }
            };
          }
        };
        tx.oncomplete = function () {
          if (stored) rememberOutbox(entry);
          resolve(stored);
        };
        tx.onerror = function () { resolve(false); };
      });
    });
  }

  function outboxRemove(key) {
    pendingActions = pendingActions.filter(function (e) { return e.key !== key; });
    announcePending();
    return outboxWrite(function (store) { store.delete(key); });
  }

  /** Forget every queued mutation (sign-out) and stop work in flight. */
  function outboxClear() {
    outboxGeneration += 1;
    pendingActions = [];
    announcePending();
    return outboxWrite(function (store) { store.clear(); }).then(function () {
      return true;
    });
  }

  /** `replay`, `hold` or `discard` (queued under another identity). */
  function outboxDisposition(entry, confirm) {
    var current = outboxScope();
    if (entry.scope) return entry.scope === current ? "replay" : current ? "discard" : "hold";
    return confirm ? "replay" : "hold";
  }

  function outboxExpired(entry, now) {
    return (
      (entry.attempts || 0) >= OUTBOX_MAX_ATTEMPTS ||
      now - (entry.at || 0) > OUTBOX_MAX_AGE_MS
    );
  }

  function heldCount() {
    return pendingActions.filter(function (e) {
      return outboxDisposition(e, false) === "hold";
    }).length;
  }

  /** Tell the page how many mutations are waiting, and whether we are offline. */
  function announcePending() {
    var count = pendingActions.length;
    var offline = navigator.onLine === false;
    var root = doc.documentElement;
    if (count > 0) root.setAttribute("data-rsx-pending-actions", String(count));
    else root.removeAttribute("data-rsx-pending-actions");
    doc.querySelectorAll("[data-rsx-offline]").forEach(function (el) {
      el.hidden = count === 0 && !offline;
    });
    doc.dispatchEvent(
      new CustomEvent("rsx:pending", { detail: { count: count, held: heldCount(), online: !offline } })
    );
  }

  var draining = false;

  function announceOutbox(name, entry, extra) {
    doc.dispatchEvent(
      new CustomEvent(name, {
        bubbles: true,
        detail: Object.assign({ id: entry.action, key: entry.key }, extra || {})
      })
    );
  }

  /**
   * Replay the queued mutations this page may replay, oldest first. A
   * DECISION removes the entry; an ambiguous failure counts an attempt and
   * stops the drain, keeping order. `opts.confirm` includes held unscoped
   * entries. A clear stops the drain.
   */
  function drainOutbox(opts) {
    var confirm = !!(opts && opts.confirm === true);
    if (draining) return Promise.resolve(0);
    draining = true;
    var replayed = 0;
    var stopped = false;
    var generation = outboxGeneration;
    return outboxRead()
      .then(function (entries) {
        var now = Date.now();
        return entries.reduce(function (chain, entry) {
          return chain.then(function () {
            if (stopped || generation !== outboxGeneration) return;
            if (outboxExpired(entry, now)) {
              return outboxRemove(entry.key).then(function () {
                announceOutbox("rsx:action-expired", entry, { attempts: entry.attempts || 0 });
              });
            }
            var disposition = outboxDisposition(entry, confirm);
            if (disposition === "hold") return;
            if (disposition === "discard") {
              return outboxRemove(entry.key).then(function () {
                announceOutbox("rsx:action-discarded", entry, { reason: "identity" });
              });
            }
            return callAction(entry.action, entry.args, {
              idempotencyKey: entry.key,
              retries: 0,
              refresh: false
            }).then(
              function (envelope) {
                replayed += 1;
                return outboxRemove(entry.key).then(function () {
                  announceOutbox("rsx:action-replayed", entry, { envelope: envelope });
                });
              },
              function (error) {
                if (error && error.decided) {
                  return outboxRemove(entry.key).then(function () {
                    announceOutbox("rsx:action-refused", entry, { status: error.status });
                  });
                }
                stopped = true;
                if (generation !== outboxGeneration) return;
                var counted = Object.assign({}, entry, { attempts: (entry.attempts || 0) + 1 });
                return outboxAdd(counted, true);
              }
            );
          });
        }, Promise.resolve());
      })
      .catch(function () {})
      .then(function () {
        draining = false;
        announcePending();
        // Anything that landed changed the page underneath the reader.
        if (replayed > 0) window.__rsx.refresh();
        return replayed;
      });
  }

  // ---------------------------------------------------------------
  // actions
  // ---------------------------------------------------------------

  var ACTION_PREFIX = "/_rsx/action/";

  // The action token (csrf.rs): read from its cookie when a request is
  // sent, never queued; `/_rsx/csrf` issues one when there is none. A page
  // on plain http is a `ferrite dev` serve, whose token cookie has no
  // `__Host-` prefix (Safari keeps no Secure cookie there); anywhere else
  // only the prefixed cookie is read, since a sibling host can plant the
  // other name.
  var CSRF_COOKIE = location.protocol === "http:" ? "rsx_csrf_dev" : "__Host-rsx_csrf";
  var CSRF_FIELD = "_rsx_csrf";

  function isCsrfToken(v) {
    return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
  }

  function csrfCookie() {
    var found = "";
    String(doc.cookie || "").split(";").forEach(function (part) {
      var at = part.indexOf("=");
      if (at > 0 && part.slice(0, at).trim() === CSRF_COOKIE) found = part.slice(at + 1).trim();
    });
    return isCsrfToken(found) ? found : "";
  }

  function csrfToken() {
    var held = csrfCookie();
    if (held) return Promise.resolve(held);
    return fetch("/_rsx/csrf", { credentials: "same-origin", cache: "no-store" })
      .then(function (res) {
        if (!res.ok) throw new Error("rsx: no action token");
        return res.json();
      })
      .then(function (body) {
        var token = csrfCookie() || (body && body.token);
        if (!isCsrfToken(token)) throw new Error("rsx: no action token");
        return token;
      });
  }

  function withCsrf(args, token) {
    if (!args || typeof args !== "object" || Array.isArray(args)) return args;
    var out = Object.assign({}, args);
    out[CSRF_FIELD] = token;
    return out;
  }

  /** A native post to an action gets the cookie's token in its field. */
  // The values a native submission would send: the form's fields plus the
  // clicked submit button's name/value.
  function formValues(form, submitter) {
    var data;
    try {
      data = submitter ? new FormData(form, submitter) : new FormData(form);
    } catch (e) {
      data = new FormData(form);
      if (submitter && submitter.name) data.append(submitter.name, submitter.value || "");
    }
    return data;
  }

  function stampActionForm(form, event) {
    // The resubmission this function started already carries its token.
    if (form.__rsxStamped) {
      form.__rsxStamped = false;
      return;
    }
    var target;
    // A submitter's formaction overrides the form's action.
    var submitter = event.submitter;
    var action = (submitter && submitter.hasAttribute && submitter.hasAttribute("formaction"))
      ? submitter.getAttribute("formaction")
      : form.getAttribute("action");
    try {
      target = new URL(action || "", location.href);
    } catch (e) {
      return;
    }
    if (target.origin !== location.origin || target.pathname.indexOf(ACTION_PREFIX) !== 0) return;
    var put = function (token) {
      var field = form.querySelector('input[name="' + CSRF_FIELD + '"]');
      if (!field) {
        field = doc.createElement("input");
        field.type = "hidden";
        field.name = CSRF_FIELD;
        form.appendChild(field);
      }
      field.value = token;
    };
    var held = csrfCookie();
    if (held) return put(held);
    event.preventDefault();
    csrfToken().then(function (token) {
      put(token);
      // requestSubmit keeps the submitter (its value and formaction); the prototype
      // call survives a control named "submit" shadowing form.submit.
      if (form.requestSubmit && submitter) {
        form.__rsxStamped = true;
        form.requestSubmit(submitter);
      } else {
        HTMLFormElement.prototype.submit.call(form);
      }
    }, function () {});
  }

  /**
   * A fresh idempotency key from a CSPRNG, or null. A recorded reply is
   * returned to whoever presents its key, so it must be unguessable:
   * never Math.random or the clock.
   */
  function newKey() {
    var c = window.crypto;
    if (c && typeof c.randomUUID === "function") return c.randomUUID();
    if (c && typeof c.getRandomValues === "function") {
      var bytes = new Uint8Array(16);
      c.getRandomValues(bytes);
      var hex = "";
      for (var i = 0; i < bytes.length; i++) hex += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
      return hex;
    }
    return null;
  }

  /** A failure the server DECIDED: retrying or queueing cannot change it. */
  function decidedError(message, status) {
    var error = new Error(message);
    error.decided = true;
    error.status = status;
    return error;
  }

  /** Whether a parsed body is an action envelope (wire-v1 §4). */
  function isEnvelope(v) {
    return (
      !!v && typeof v === "object" && typeof v.v === "number" &&
      (v.status === "ok" || v.status === "error" || v.status === "pending")
    );
  }

  /** A reply that is not an envelope: decided below 500, else ambiguous. */
  function replyError(status) {
    if (status > 0 && status < 500) {
      return decidedError("rsx: the server answered " + status + " without an action reply", status);
    }
    var error = new Error("rsx: malformed action reply");
    error.status = status;
    return error;
  }

  /**
   * Apply the re-render an action returned with its answer.
   *
   * The server rendered this AFTER committing the mutation and
   * invalidating its cache tags, so it is the new state — and it
   * arrived in the SAME response, so applying it costs no request at
   * all. A payload that cannot be applied falls back to an ordinary
   * refresh rather than leaving the page stale.
   */
  function applyRefresh(payload) {
    if (!canApply(payload)) return window.__rsx.refresh();
    return withTransition(function () {
      if (applyPayload(payload)) {
        settle(new URL(location.href), { preserve: true });
      }
    });
  }

  /**
   * Call an action.
   *
   * The idempotency key is minted ONCE per logical submission and
   * REUSED on every retry. That is the whole reason a retry is safe:
   * the server recognizes the duplicate and replays what it already
   * decided, instead of applying the effect a second time. Minting a
   * fresh key per attempt would turn one click into several mutations.
   */
  function callAction(id, args, opts) {
    opts = opts || {};
    var key = opts.idempotencyKey || newKey();
    var retries = opts.retries === undefined ? 2 : opts.retries;
    if (!key) {
      if (opts.undo) opts.undo();
      return Promise.reject(
        decidedError("rsx: this browser has no secure random source, so the action was not sent", 0)
      );
    }

    var attempt = function (left) {
      var headers = {
        "content-type": "application/json",
        "idempotency-key": key,
        "x-rsx-action": "1",
        // Which page the reader is looking at, and what they already
        // have of it. With both, the server can answer the mutation AND
        // the new render together — one round trip instead of two.
        "x-rsx-path": location.pathname + location.search
      };
      var basis = haveHeader();
      if (basis) headers["x-rsx-have"] = basis;
      return csrfToken()
        .then(function (token) {
          return fetch(ACTION_PREFIX + encodeURIComponent(id), {
            method: "POST",
            credentials: "same-origin",
            headers: headers,
            body: JSON.stringify(withCsrf(args || {}, token))
          });
        })
        .then(function (res) {
          // An action's failures are DATA: the envelope carries the
          // code and the field messages, and the status matches it.
          // Anything else is classified by HTTP status (`replyError`).
          return res.json().then(
            function (envelope) {
              if (isEnvelope(envelope)) return envelope;
              throw replyError(res.status || 0);
            },
            function () {
              throw replyError(res.status || 0);
            }
          );
        })
        .catch(function (e) {
          if (e && e.decided) throw e;
          // Retry only while the reader is still who pressed.
          var sameReader = opts.scope === undefined || opts.scope === outboxScope();
          if (left > 0 && sameReader) return attempt(left - 1);
          throw e;
        });
    };

    return attempt(retries).then(function (envelope) {
      if (envelope && envelope.expired_tags && envelope.expired_tags.length) {
        window.__rsx.invalidate(envelope.expired_tags);
      }
      if (envelope && envelope.status === "ok") {
        if (envelope.redirect && isLocalPath(envelope.redirect)) {
          navigate(envelope.redirect, {});
        } else if (envelope.redirect) {
          // Only a local path is followed, as on the no-JS form path.
          if (window.console) console.warn("rsx: ignored an action redirect that is not a local path");
          if (opts.refresh !== false) window.__rsx.refresh();
        } else if (envelope.refresh) {
          // The answer carried the new render: apply it directly.
          applyRefresh(envelope.refresh);
        } else if (opts.refresh !== false) {
          window.__rsx.refresh();
        }
      } else if (opts.undo) {
        // The server REFUSED: the optimistic change was a lie, so it is
        // taken back before the error is shown.
        opts.undo();
      }
      return envelope;
    }, function (error) {
      // An ambiguous transport failure: the mutation may or may not
      // have been applied, so showing it as applied would be a guess.
      // Roll back and let the retry decide.
      if (opts.undo) opts.undo();
      throw error;
    });
  }

  function showFieldErrors(form, envelope) {
    form.querySelectorAll("[data-rsx-error]").forEach(function (el) {
      el.removeAttribute("data-rsx-error");
      el.textContent = "";
    });
    // Clear the PREVIOUS submission's invalid marks first, or a field
    // the user has since corrected stays announced as invalid.
    form.querySelectorAll('[aria-invalid="true"]').forEach(function (el) {
      el.removeAttribute("aria-invalid");
    });
    var fields = (envelope && envelope.error && envelope.error.fields) || {};
    Object.keys(fields).forEach(function (name) {
      var target = form.querySelector('[data-rsx-error-for="' + cssEscape(name) + '"]');
      if (target) {
        target.setAttribute("data-rsx-error", "");
        target.textContent = fields[name];
      }
      var input = form.querySelector('[name="' + cssEscape(name) + '"]');
      if (input) input.setAttribute("aria-invalid", "true");
    });
  }

  /**
   * Run ONE submission: optimistic update, action call, field errors,
   * and the outbox on an ambiguous failure.
   *
   * `args` and `key` are captured when the reader PRESSED, not when this
   * runs — a queued submission must carry the values it was made with,
   * and its own idempotency key, or the second of two quick edits would
   * be submitted with the first one's data.
   */
  function submitForm(form, id, args, key, scope, generation) {
    form.setAttribute("data-rsx-pending", "");
    // The optimistic change lands NOW, before the request is sent, and
    // carries its own undo. That is the whole point: the interface
    // answers at the speed of the click, and corrects itself only if
    // the server disagrees. Guarded twice — here and per operation —
    // because this runs AFTER the form is marked pending, so anything
    // that threw would leave it stuck with no request in flight.
    var undo = function () {};
    try {
      undo = applyOptimistic(form, form.getAttribute("data-rsx-optimistic"));
    } catch (e) {
      if (window.console) console.warn("rsx: optimistic update skipped", e);
    }
    var finish = function () {
      form.__rsxInflight = Math.max(0, (form.__rsxInflight || 1) - 1);
      if (form.__rsxInflight === 0) form.removeAttribute("data-rsx-pending");
    };

    return callAction(id, args, { idempotencyKey: key, undo: undo, scope: scope })
      .then(function (envelope) {
        showFieldErrors(form, envelope);
        form.removeAttribute("data-rsx-failed");
        // THIS submission is now decided, so its retry association is
        // spent: leaving it would make a later, deliberate submission of
        // the same values reuse a key the server has already answered,
        // and the reader would get the old reply instead of a new
        // mutation. The check is conditional so a DIFFERENT submission's
        // association — still queued, still owning its own key — is not
        // erased by this one finishing.
        if (form.__rsxFailed && form.__rsxFailed.key === key) {
          form.__rsxFailed = null;
        }
        // A PREVIOUS attempt may have queued this key. The server has
        // now decided, so the entry is spent: leaving it would report a
        // delivered mutation as pending and replay it again later.
        outboxRemove(key);
        if (envelope && envelope.status === "ok") form.reset();
        finish();
        form.dispatchEvent(
          new CustomEvent("rsx:action", { bubbles: true, detail: { id: id, envelope: envelope } })
        );
      })
      .catch(function (e) {
        finish();
        form.setAttribute("data-rsx-failed", "");
        if (e && e.decided) {
          // Answered, just not with an envelope: queueing it would
          // replay a request that can only be refused again.
          if (form.__rsxFailed && form.__rsxFailed.key === key) form.__rsxFailed = null;
          outboxRemove(key);
          form.dispatchEvent(
            new CustomEvent("rsx:action-failed", {
              bubbles: true,
              detail: { id: id, error: String(e), status: e.status, retryable: false, queued: false }
            })
          );
          return;
        }
        // An ambiguous failure: the action may or may not have been
        // applied. Re-submitting the form NATIVELY would be the obvious
        // fallback and is exactly wrong — a form POST cannot set the
        // `idempotency-key` header, so the server would see a fresh
        // request and could apply the effect a SECOND time. Instead the
        // submission is QUEUED under this key (the outbox replays it on
        // reconnect) and REMEMBERED, so that a reader pressing the button
        // again retries THIS submission instead of starting another one.
        form.__rsxFailed = { key: key, args: JSON.stringify(args) };
        // Queued as the presser; not at all after a clear (sign-out).
        var entry = { key: key, action: id, args: args, at: Date.now(), attempts: 0, scope: scope };
        var queue = generation === outboxGeneration ? outboxAdd(entry) : Promise.resolve(false);
        return queue.then(function (queued) {
          form.dispatchEvent(
            new CustomEvent("rsx:action-failed", {
              bubbles: true,
              detail: { id: id, error: String(e), retryable: true, queued: queued }
            })
          );
        });
      });
  }

  function onSubmit(event) {
    var form = event.target;
    if (!form || form.tagName !== "FORM" || event.defaultPrevented) return;
    var id = form.getAttribute("data-rsx-action");
    if (!id || form.__rsxFallback) return stampActionForm(form, event);
    event.preventDefault();

    // Values and key are captured NOW, at the press; the token field is
    // added when the request is sent.
    var args = {};
    formValues(form, event.submitter).forEach(function (value, name) {
      if (name !== CSRF_FIELD) args[name] = value;
    });
    // A press that repeats a submission which failed AMBIGUOUSLY is a
    // RETRY, not a second mutation: reusing that submission's key is what
    // makes it safe — if the first attempt did commit, the server replays
    // its recorded answer rather than applying the effect twice. Anything
    // else (different values, or a form with nothing outstanding) is a new
    // logical mutation and gets its own key.
    var argsJson = JSON.stringify(args);
    var outstanding = form.__rsxFailed;
    var key = outstanding && outstanding.args === argsJson ? outstanding.key : newKey();
    var scope = outboxScope();
    var generation = outboxGeneration;
    form.__rsxInflight = (form.__rsxInflight || 0) + 1;

    // Repeated submissions RUN IN ORDER rather than being dropped. A
    // reader who edits the same thing twice quickly must not have the
    // second overtake the first — the durable state would end up
    // reflecting the earlier edit — and refusing the second press (what
    // this did before) discards intent silently: the click does nothing
    // and nothing says so. One chain per form IS the ordering guarantee,
    // and a failure must not break it for everything behind it.
    var run = function () {
      return submitForm(form, id, args, key, scope, generation);
    };
    form.__rsxChain = (form.__rsxChain || Promise.resolve()).then(run, run);
  }

  // ---------------------------------------------------------------
  // client data fetching
  // ---------------------------------------------------------------

  /*
   * A small READ cache for an island that needs data the page did not
   * carry: deduped by URL, TTL'd, revalidated when the tab regains
   * focus, optionally polled.
   *
   * Deliberately not a general data layer. Server rendering is the
   * default and a page carries its own data through its loader; this is
   * for what genuinely belongs to the client — a widget that refreshes
   * while the tab is open, a panel opened on demand — and it stays small
   * enough to read in one sitting.
   */
  var dataCache = new Map();
  var dataInflight = new Map();
  var watchers = new Set();
  var DEFAULT_DATA_TTL_MS = 15000;
  /// The most URLs the read cache keeps. Unbounded, a long-lived tab
  /// watching many endpoints would grow forever — the payload cache is
  /// bounded for the same reason.
  var DATA_CACHE_MAX = 64;

  function clientFetch(url, opts) {
    opts = opts || {};
    var ttl = opts.ttl === undefined ? DEFAULT_DATA_TTL_MS : opts.ttl;
    var entry = dataCache.get(url);
    if (!opts.force && entry && Date.now() - entry.at < ttl) {
      return Promise.resolve(entry.data);
    }
    // ONE request per URL in flight: a page with four widgets reading the
    // same endpoint must not open four connections.
    if (dataInflight.has(url)) return dataInflight.get(url);
    var request = fetch(url, {
      credentials: "same-origin",
      headers: { accept: "application/json" }
    })
      .then(function (res) {
        if (!res.ok) throw new Error("rsx: HTTP " + res.status);
        var type = res.headers.get("content-type") || "";
        return type.indexOf("application/json") === -1 ? res.text() : res.json();
      })
      .then(function (data) {
        dataCache.set(url, { at: Date.now(), data: data });
        while (dataCache.size > DATA_CACHE_MAX) {
          dataCache.delete(dataCache.keys().next().value);
        }
        doc.dispatchEvent(new CustomEvent("rsx:data", { detail: { url: url, data: data } }));
        return data;
      });
    dataInflight.set(url, request);
    var settle = function () {
      dataInflight.delete(url);
    };
    request.then(settle, settle);
    return request;
  }

  /**
   * Watch a URL: `cb(data)` is called with the current value (from cache
   * when fresh) and again on every revalidation. Returns an unsubscribe
   * function — a watcher that cannot be stopped is a leak, and an island
   * removed by a navigation must be able to stop.
   */
  function watchData(url, cb, opts) {
    opts = opts || {};
    var stopped = false;
    var timer = null;
    var watcher = null;
    // Declared before `load`, which calls it when a watched element has
    // been detached.
    var stop = function () {
      stopped = true;
      if (watcher) watchers.delete(watcher);
      if (timer) clearInterval(timer);
    };
    var deliver = function (data) {
      if (stopped) return;
      try {
        cb(data);
      } catch (e) {
        if (window.console) console.error("rsx: a data watcher threw", e);
      }
    };
    var load = function (force) {
      // An island removed by a navigation cannot run its own cleanup, so a
      // watcher given its element stops itself when that element is gone.
      // Without this a patched-away widget would keep polling forever,
      // invisibly — the same failure a live region avoids by checking
      // `isConnected`.
      if (opts.el && !opts.el.isConnected) {
        stop();
        return Promise.resolve();
      }
      return clientFetch(url, { ttl: opts.ttl, force: force }).then(deliver, function (e) {
        if (window.console) console.warn("rsx: data fetch failed", url, e);
      });
    };
    watcher = {
      url: url,
      el: opts.el || null,
      stop: stop,
      revalidate: function () {
        // Detachment is checked BEFORE the focus preference: a watcher
        // that opted out of focus revalidation still has to be able to
        // die with its element.
        if (opts.el && !opts.el.isConnected) {
          stop();
          return;
        }
        if (opts.focus !== false) load(true);
      }
    };
    watchers.add(watcher);
    load(false);
    if (opts.poll) {
      // Polling PAUSES while the tab is hidden: a background tab that
      // keeps polling spends a reader's battery and a server's capacity
      // on data nobody is looking at.
      timer = setInterval(function () {
        if (!doc.hidden) load(true);
      }, Math.max(1000, opts.poll));
    }
    return stop;
  }

  function revalidateWatched() {
    watchers.forEach(function (w) {
      w.revalidate();
    });
  }

  /**
   * Stop every watcher whose element a navigation removed.
   *
   * Detachment has to be noticed INDEPENDENTLY of fetching: a watcher
   * with `{ focus: false }` and no polling would otherwise never run
   * again, so nothing would ever observe that its element is gone and its
   * entry (and any timer) would live for the life of the tab. This is the
   * same discipline `closeDetachedLive` applies to live regions, and it
   * runs from the same place.
   */
  function sweepWatchers() {
    watchers.forEach(function (w) {
      if (w.el && !w.el.isConnected) w.stop();
    });
  }

  // ---------------------------------------------------------------
  // history
  // ---------------------------------------------------------------

  function onPopState(event) {
    var state = event.state || {};
    var url = location.pathname + location.search;
    var scrollTo = typeof state.scroll === "number" ? state.scroll : 0;
    navigate(url, { push: false, scrollTo: scrollTo }).then(function () {
      window.scrollTo(0, scrollTo);
    });
  }

  // ---------------------------------------------------------------
  // public surface
  // ---------------------------------------------------------------

  window.__rsx = {
    ready: true,
    islands: islands,
    /** Register an island factory: `__rsx.island("counter", fn)`. */
    island: function (name, factory) {
      islands[name] = factory;
      hydrateIslands();
    },
    navigate: navigate,
    /** Call an action by id. */
    action: callAction,
    /** Read JSON for an island: deduped, TTL'd, focus-revalidated. */
    fetch: clientFetch,
    /** Watch a URL; returns an unsubscribe function. */
    watch: watchData,
    /** Replay queued mutations now; `{ confirm: true }` includes held ones. */
    drain: drainOutbox,
    /** Forget every queued mutation (sign-out). */
    clearOutbox: outboxClear,
    /** The mutations still waiting to be delivered. */
    pending: function () {
      return pendingActions.slice();
    },
    /** Parse an optimistic spec (the grammar, as data). */
    parseOptimistic: parseOptimistic,
    /** Apply an optimistic update, returning its undo. */
    optimistic: applyOptimistic,
    prefetch: function (url) {
      return fetchPayload(url, { prefetch: true });
    },
    /** Drop cached payloads carrying any of these tags. */
    invalidate: function (tags) {
      var list = [].concat(tags || []);
      cache.forEach(function (entry, url) {
        if (entry.tags.some(function (t) { return list.indexOf(t) !== -1; })) cache.delete(url);
      });
    },
    /** Re-render the current URL, bypassing the cache. */
    refresh: function () {
      // `preserve` is what makes this a refresh rather than a
      // navigation: the page's content is replaced, and the reader's
      // scroll position, focus and permanent elements are not.
      return navigate(location.pathname + location.search, {
        push: false,
        force: true,
        preserve: true
      });
    },
    cache: cache
  };

  // ---------------------------------------------------------------
  // boot
  // ---------------------------------------------------------------

  if ("scrollRestoration" in history) history.scrollRestoration = "manual";
  readState();
  doc.addEventListener("click", onClick);
  doc.addEventListener("submit", onSubmit);
  doc.addEventListener("mouseover", onIntent, { passive: true });
  doc.addEventListener("touchstart", onIntent, { passive: true });
  window.addEventListener("popstate", onPopState);
  window.addEventListener("online", function () {
    announcePending();
    drainOutbox();
    // Data read while offline is suspect, and a reconnect is exactly when
    // a reader expects to be looking at current values.
    revalidateWatched();
  });
  window.addEventListener("offline", announcePending);
  doc.addEventListener("visibilitychange", function () {
    if (!doc.hidden) revalidateWatched();
  });
  // A submission queued in a PREVIOUS page load is replayed as soon as
  // this one starts, under its original key, if it may be (see the
  // outbox notes); otherwise it is held.
  outboxRead().then(function (entries) {
    if (entries.length) drainOutbox();
    else announcePending();
  });
  observeLinks();
  hydrateIslands();
  fillSlots();
  openLiveRegions();
  markTransitionNames();
  doc.documentElement.setAttribute("data-rsx-ready", "");
})();
