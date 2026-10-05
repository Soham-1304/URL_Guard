import React, { useEffect, useRef } from 'react';
import { feats, score } from '../lib/features';

interface RowSegment {
  a: number;
  b: number;
  url: string;
  p: number;
}

interface CanvasRow {
  s: string;
  segs: RowSegment[];
  L: number;
  off: number;
  v: number;
}

export const BackgroundCanvas: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    const cx = cv.getContext('2d');
    if (!cx) return;

    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const R = <T,>(a: T[]): T => a[(Math.random() * a.length) | 0];
    const rs = (n: number) =>
      Array.from({ length: n }, () =>
        'abcdefghijklmnopqrstuvwxyz0123456789'[(Math.random() * 36) | 0]
      ).join('');

    const GOOD = [
      'wikipedia.org/wiki/',
      'github.com/',
      'docs.python.org/3/library/',
      'stackoverflow.com/questions/',
      'nytimes.com/2026/',
      'developer.mozilla.org/en-US/docs/',
      'arxiv.org/abs/',
      'youtube.com/watch?v=',
      'en.wikipedia.org/wiki/',
      'medium.com/@',
      'kaggle.com/datasets/',
      'scikit-learn.org/stable/modules/'
    ];

    const mkGood = () =>
      'https://' +
      R(['www.', '']) +
      R(GOOD) +
      R([
        'Random_forest',
        'pandas',
        '2504.' + rs(5),
        'ensemble',
        'machine-learning',
        rs(8),
        'Phishing',
        'index.html'
      ]);

    const mkBad = () => {
      const k = (Math.random() * 5) | 0;
      const b = R(['paypal', 'google', 'amazon', 'netflix', 'hdfcbank', 'microsoft']);
      const w = R(['login', 'verify', 'secure', 'account', 'update', 'signin']);
      if (k === 0) {
        return `http://${rs(3)}.${rs(3)}.${rs(2)}.${rs(2)}:${
          (1000 + Math.random() * 60000) | 0
        }/${R(['bin.sh', 'mirai.x86', 'a.exe', 'payload'])}`.replace(
          /[a-z]/g,
          () => String((Math.random() * 255) | 0)
        );
      } else if (k === 1) {
        return `http://${b}-${w}-${R(['account', 'security', 'alert'])}.${R([
          'xyz',
          'top',
          'click',
          'tk'
        ])}/${w}.php?${R(['id', 'session', 'token'])}=${rs(8)}`;
      } else if (k === 2) {
        return `http://${w}.${b}.${rs(6)}.${R(['com', 'net', 'icu'])}/${w}/${rs(5)}?ref=${rs(
          6
        )}&u=${rs(4)}`;
      } else if (k === 3) {
        return `http://${b.replace(/o/g, '0').replace(/l/g, '1')}-${w}.${R([
          'xyz',
          'top',
          'work'
        ])}/${w}-identity`;
      } else {
        return `http://free-${R(['gift', 'bonus', 'prize', 'crypto'])}-${rs(4)}.${R([
          'top',
          'click',
          'buzz'
        ])}/a/b/c/${rs(3)}.php?x=${rs(4)}&y=${rs(4)}&z=${rs(3)}`;
      }
    };

    let rows: CanvasRow[] = [];
    let W = window.innerWidth;
    let H = window.innerHeight;
    let cw = 8;
    const LH = 21;
    let mx = -1;
    let my = -1;
    let last = 0;
    let animId = 0;

    function mkRow(i: number): CanvasRow {
      const segs: RowSegment[] = [];
      let s = '';
      let len = 0;
      const target = Math.ceil(W / cw) * 1.6 + 40;
      while (len < target) {
        const url = Math.random() < 0.5 ? mkGood() : mkBad();
        const f = feats(url);
        const sc = f ? score(f) : { p: 0.5, why: [] };
        segs.push({ a: s.length, b: s.length + url.length, url, p: sc.p });
        s += url + '   ';
        len = s.length;
      }
      return {
        s,
        segs,
        L: s.length,
        off: Math.random() * s.length * cw,
        v: (8 + Math.random() * 20) * (i % 2 ? 1 : -1)
      };
    }

    function size() {
      if (!cv || !cx) return;
      const d = window.devicePixelRatio || 1;
      W = window.innerWidth;
      H = window.innerHeight;
      cv.width = W * d;
      cv.height = H * d;
      cx.setTransform(d, 0, 0, d, 0, 0);
      cx.font = '400 13px "Geist Mono", ui-monospace, Menlo, monospace';
      cw = cx.measureText('M').width || 8;
      rows = Array.from({ length: Math.ceil(H / LH) + 1 }, (_, i) => mkRow(i));
    }

    function draw(t: number) {
      if (!cx) return;
      const dt = Math.min(0.05, (t - last) / 1000 || 0);
      last = t;
      cx.clearRect(0, 0, W, H);
      cx.font = '400 13px "Geist Mono", ui-monospace, Menlo, monospace';
      cx.textBaseline = 'middle';

      const hr = my >= 0 ? Math.floor(my / LH) : -9;

      rows.forEach((r, i) => {
        if (!reduce) {
          r.off = (r.off + r.v * dt + r.L * cw * 4) % (r.L * cw);
        }
        const P = r.L * cw;
        const x0 = -r.off;
        const y = i * LH + LH / 2;
        const near = Math.abs(i - hr);

        cx.fillStyle =
          near === 0
            ? 'rgba(20,22,27,.065)'
            : near === 1
            ? 'rgba(20,22,27,.04)'
            : 'rgba(95,106,125,.028)';
        cx.fillText(r.s, x0, y);
        cx.fillText(r.s, x0 + P, y);

        if (near === 0) {
          let ci = ((mx - x0) / cw) | 0;
          ci = ((ci % r.L) + r.L) % r.L;
          const sg = r.segs.find(g => ci >= g.a && ci < g.b);
          if (sg) {
            const bad = sg.p >= 0.5;
            const col = bad ? '217,45,58' : '18,128,92';
            [x0, x0 + P].forEach(bx => {
              const x = bx + sg.a * cw;
              if (x + sg.url.length * cw > 0 && x < W) {
                cx.fillStyle = `rgba(${col},.08)`;
                cx.fillRect(x - 3, y - LH / 2 + 1, sg.url.length * cw + 6, LH - 2);
                cx.fillStyle = `rgb(${col})`;
                cx.fillText(sg.url, x, y);
              }
            });
          }
        }
      });

      animId = requestAnimationFrame(draw);
    }

    const onPointerMove = (e: PointerEvent) => {
      const target = e.target as HTMLElement | null;
      if (target?.closest('.solid, nav, .btn, input, button, .tin, details, .code, footer, .chips')) {
        mx = my = -1;
      } else {
        mx = e.clientX;
        my = e.clientY;
      }
    };

    const onPointerLeave = () => {
      mx = my = -1;
    };

    let rz: ReturnType<typeof setTimeout> | undefined;
    const onResize = () => {
      clearTimeout(rz);
      rz = setTimeout(size, 200);
    };

    window.addEventListener('pointermove', onPointerMove);
    document.addEventListener('pointerleave', onPointerLeave);
    window.addEventListener('resize', onResize);

    if (document.fonts?.ready) {
      document.fonts.ready.then(() => {
        size();
        animId = requestAnimationFrame(draw);
      });
    } else {
      size();
      animId = requestAnimationFrame(draw);
    }

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('pointermove', onPointerMove);
      document.removeEventListener('pointerleave', onPointerLeave);
      window.removeEventListener('resize', onResize);
      clearTimeout(rz);
    };
  }, []);

  return <canvas id="bg" ref={canvasRef} aria-hidden="true" />;
};
