/* ============================================================
   ThreatWeaver — shared client behaviour
   1. Theme toggle (dark default, persisted in localStorage)
   2. In-app guided tour / onboarding
   No external dependencies — runs on every page via base.html.
   ============================================================ */
(function () {
    'use strict';

    // ---------------------------------------------------------------
    // 1. THEME
    // ---------------------------------------------------------------
    const THEME_KEY = 'tw-theme';
    const root = document.documentElement;

    function applyTheme(theme) {
        if (theme === 'light') {
            root.classList.add('light');
            root.classList.remove('dark');
        } else {
            root.classList.add('dark');
            root.classList.remove('light');
        }
    }

    // Default to dark unless the user has explicitly chosen light before.
    const savedTheme = localStorage.getItem(THEME_KEY) || 'dark';
    applyTheme(savedTheme);

    window.toggleTheme = function () {
        const next = root.classList.contains('light') ? 'dark' : 'light';
        localStorage.setItem(THEME_KEY, next);
        applyTheme(next);
    };

    // ---------------------------------------------------------------
    // 2. GUIDED TOUR
    // ---------------------------------------------------------------
    // Each page defines its own steps below. A step targets a CSS selector
    // (or null for a centered intro/outro card). Steps whose target is not
    // present on the current page are skipped automatically.
    const TOURS = {
        dashboard: [
            {
                title: 'Welcome to ThreatWeaver',
                body: 'ThreatWeaver autonomously finds, proves, and patches web-app vulnerabilities — then writes the report. This quick tour shows you around. You can replay it anytime from the "Guide" button in the top bar.',
                selector: null
            },
            {
                title: '1 · Create a workspace',
                body: 'A workspace is a target domain you own. Type the domain (e.g. example.com) and create it. You can only scan domains you control.',
                selector: '[data-tour="create-workspace"]'
            },
            {
                title: '2 · Open a workspace',
                body: 'Your workspaces are listed here. Click anywhere on a row to open it and start the verification + scanning flow.',
                selector: '[data-tour="workspace-list"]'
            },
            {
                title: 'Manage your account',
                body: 'Click your profile here to open account settings — manage your email, password, security, and sign out.',
                selector: '[data-tour="account"]'
            },
            {
                title: 'Switch themes',
                body: 'Prefer a lighter look? Toggle between dark and light mode here. Your choice is remembered.',
                selector: '[data-tour="theme"]'
            },
            {
                title: "You're set",
                body: 'Create a workspace, verify the domain, then start a scan. Press "Guide" in the top bar to see this again.',
                selector: null
            }
        ],
        workspace: [
            {
                title: 'Workspace',
                body: 'This is a single target. Before you can scan it, you must prove you own the domain via a DNS record.',
                selector: null
            },
            {
                title: '1 · Add the DNS record',
                body: 'Create a DNS TXT record using the name and value shown here. This proves ownership so scanning is authorized.',
                selector: '[data-tour="dns-verify"]'
            },
            {
                title: '2 · Verify the domain',
                body: 'Once the TXT record is live, click "Verify domain". ThreatWeaver re-checks DNS and unlocks scanning when it matches.',
                selector: '[data-tour="verify-btn"]'
            },
            {
                title: '3 · Start a scan',
                body: 'After verification, launch an autonomous scan from here. You\'ll be taken to a live view of the attack.',
                selector: '[data-tour="jobs-section"]'
            },
            {
                title: 'Review past scans',
                body: 'Previous analysis jobs appear in this table. Click any row to reopen its live attack graph and report.',
                selector: '[data-tour="jobs-table"]'
            }
        ],
        job: [
            {
                title: 'Live scan view',
                body: 'Everything on this page updates in real time — no refresh needed. Watch the AI work through recon, exploitation, verification, and patching.',
                selector: null
            },
            {
                title: 'Scan status & timer',
                body: 'Track whether the scan is starting, running live, or complete — plus how long it has been running.',
                selector: '[data-tour="scan-status"]'
            },
            {
                title: 'K2 thought process',
                body: 'See the AI reason step-by-step as it decides what to attack next. Each step appears live as it happens.',
                selector: '[data-tour="thought-process"]'
            },
            {
                title: 'Attack graph',
                body: 'A visual map of the attack: recon → scanning → findings → proof-of-concept → patch. Drag to pan, and scroll to zoom toward your cursor.',
                selector: '[data-tour="attack-graph"]'
            },
            {
                title: 'Token usage',
                body: 'This sidebar tracks K2-Think-v2 token usage live and stays visible while you scroll.',
                selector: '[data-tour="token-sidebar"]'
            },
            {
                title: 'Mitigations',
                body: 'For every confirmed vulnerability, the AI writes a recommended fix and patched code. They appear here as findings land.',
                selector: '[data-tour="mitigations"]'
            },
            {
                title: 'Download the report',
                body: 'When the scan completes, an overall severity and a downloadable PDF report appear at the top of the page.',
                selector: null
            }
        ]
    };

    function detectPage() {
        if (document.querySelector('#attackGraphCanvas')) return 'job';
        if (document.querySelector('#verify-btn')) return 'workspace';
        if (document.querySelector('#create-workspace-form')) return 'dashboard';
        return null;
    }

    let tourState = null;

    function clearTourDom() {
        document.querySelectorAll('.tw-tour-ring, .tw-tour-pop, .tw-tour-overlay-block')
            .forEach(function (el) { el.remove(); });
        window.removeEventListener('resize', repositionTour);
        window.removeEventListener('scroll', repositionTour, true);
    }

    function endTour(markDone) {
        if (tourState && markDone) {
            try { localStorage.setItem('tw-tour-' + tourState.page, '1'); } catch (e) {}
        }
        tourState = null;
        clearTourDom();
    }

    function repositionTour() {
        if (!tourState) return;
        const step = tourState.steps[tourState.index];
        const ring = document.querySelector('.tw-tour-ring');
        const pop = document.querySelector('.tw-tour-pop');
        if (!pop) return;

        const target = step.selector ? document.querySelector(step.selector) : null;

        if (!target) {
            if (ring) ring.style.display = 'none';
            pop.classList.add('is-center');
            pop.style.top = '';
            pop.style.left = '';
            return;
        }

        pop.classList.remove('is-center');
        const r = target.getBoundingClientRect();
        const pad = 8;
        if (ring) {
            ring.style.display = 'block';
            ring.style.top = (window.scrollY + r.top - pad) + 'px';
            ring.style.left = (window.scrollX + r.left - pad) + 'px';
            ring.style.width = (r.width + pad * 2) + 'px';
            ring.style.height = (r.height + pad * 2) + 'px';
        }

        // Position the popover: prefer below, else above, clamped to viewport.
        const popW = pop.offsetWidth || 320;
        const popH = pop.offsetHeight || 160;
        let top = window.scrollY + r.bottom + 14;
        if (r.bottom + popH + 24 > window.innerHeight) {
            top = window.scrollY + r.top - popH - 14;
            if (top < window.scrollY + 8) {
                top = window.scrollY + Math.max(8, (window.innerHeight - popH) / 2);
            }
        }
        let left = window.scrollX + r.left;
        const maxLeft = window.scrollX + window.innerWidth - popW - 12;
        if (left > maxLeft) left = maxLeft;
        if (left < window.scrollX + 12) left = window.scrollX + 12;
        pop.style.top = top + 'px';
        pop.style.left = left + 'px';
    }

    function renderStep() {
        clearTourDom();
        if (!tourState) return;
        const step = tourState.steps[tourState.index];
        const total = tourState.steps.length;
        const isLast = tourState.index === total - 1;
        const isFirst = tourState.index === 0;

        const target = step.selector ? document.querySelector(step.selector) : null;
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        // Invisible click-blocker so the page can't be interacted with mid-tour.
        const block = document.createElement('div');
        block.className = 'tw-tour-overlay-block';
        block.addEventListener('click', function () { endTour(true); });
        document.body.appendChild(block);

        const ring = document.createElement('div');
        ring.className = 'tw-tour-ring';
        ring.style.display = 'none';
        document.body.appendChild(ring);

        const pop = document.createElement('div');
        pop.className = 'tw-tour-pop';
        var dots = '';
        for (var i = 0; i < total; i++) {
            dots += '<span class="tw-tour-dot' + (i === tourState.index ? ' active' : '') + '"></span>';
        }
        pop.innerHTML =
            '<div class="tw-tour-eyebrow">Guide · ' + (tourState.index + 1) + ' / ' + total + '</div>' +
            '<div class="tw-tour-title"></div>' +
            '<div class="tw-tour-body"></div>' +
            '<div class="tw-tour-foot">' +
                '<div class="tw-tour-dots">' + dots + '</div>' +
                '<div class="tw-tour-actions">' +
                    '<button type="button" class="btn btn-ghost btn-sm" data-tour-skip>Skip</button>' +
                    (isFirst ? '' : '<button type="button" class="btn btn-secondary btn-sm" data-tour-prev>Back</button>') +
                    '<button type="button" class="btn btn-primary btn-sm" data-tour-next>' + (isLast ? 'Done' : 'Next') + '</button>' +
                '</div>' +
            '</div>';
        // Use textContent for untrusted-free but simple content insertion.
        pop.querySelector('.tw-tour-title').textContent = step.title;
        pop.querySelector('.tw-tour-body').textContent = step.body;
        document.body.appendChild(pop);

        pop.querySelector('[data-tour-skip]').addEventListener('click', function () { endTour(true); });
        pop.querySelector('[data-tour-next]').addEventListener('click', function () {
            if (isLast) { endTour(true); return; }
            tourState.index++;
            renderStep();
        });
        var prevBtn = pop.querySelector('[data-tour-prev]');
        if (prevBtn) prevBtn.addEventListener('click', function () {
            tourState.index = Math.max(0, tourState.index - 1);
            renderStep();
        });

        window.addEventListener('resize', repositionTour);
        window.addEventListener('scroll', repositionTour, true);
        // Position after layout settles (and after smooth scroll begins).
        setTimeout(repositionTour, 60);
        setTimeout(repositionTour, 360);
    }

    function startTour(page) {
        const defs = TOURS[page];
        if (!defs) return;
        // Keep only steps whose target exists (null-target intro/outro always kept).
        const steps = defs.filter(function (s) {
            return !s.selector || document.querySelector(s.selector);
        });
        if (!steps.length) return;
        tourState = { page: page, steps: steps, index: 0 };
        renderStep();
    }

    window.startGuide = function () {
        const page = detectPage();
        if (page) startTour(page);
    };

    // ---------------------------------------------------------------
    // 3. CLICKABLE TABLE ROWS
    // Any <tr data-href="..."> navigates on click. Clicks on inner links
    // or buttons are left alone so nested actions still work.
    // ---------------------------------------------------------------
    document.addEventListener('click', function (e) {
        const row = e.target.closest('[data-href]');
        if (!row) return;
        if (e.target.closest('a, button')) return; // let real controls win
        window.location.href = row.getAttribute('data-href');
    });

    // Auto-start once per page type on first visit.
    document.addEventListener('DOMContentLoaded', function () {
        const page = detectPage();
        if (!page) return;
        var done = false;
        try { done = localStorage.getItem('tw-tour-' + page) === '1'; } catch (e) {}
        if (!done) {
            setTimeout(function () { startTour(page); }, 700);
        }
    });
})();
