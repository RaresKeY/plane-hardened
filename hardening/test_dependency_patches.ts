/* eslint-disable no-await-in-loop -- Keep published entrypoint imports and prototype observations ordered and bounded. */
// Published-package positive controls and regressions for exact maintained patches.
import { strict as assert } from "node:assert";
import { join } from "node:path";

const root = Bun.argv[2];
const mode = Bun.argv[3];
assert(root && (mode === "baseline" || mode === "patched"));
const vulnerable = mode === "baseline";
let controls = 0;
const artifacts: Record<string, string> = {};

function packageDirectory(name: string, version: string): string {
  const matches = [
    ...new Bun.Glob(`${name.replaceAll("/", "+")}@${version}*/node_modules/${name}/package.json`).scanSync(
      join(root, "node_modules/.bun")
    ),
  ];
  assert.equal(matches.length, 1, `Require exactly one frozen ${name}@${version} payload`);
  return join(root, "node_modules/.bun", matches[0]!, "..");
}

const tiptap = packageDirectory("@tiptap/core", "2.26.3");
const poison = JSON.parse('{"__proto__":{"data-poison-marker":"synthetic-poison"}}');
for (const file of ["dist/index.cjs", "dist/index.js", "dist/index.umd.js"]) {
  const path = join(tiptap, file);
  artifacts[`@tiptap/core/${file}`] = new Bun.CryptoHasher("sha256")
    .update(await Bun.file(path).arrayBuffer())
    .digest("hex");
  const module = await import(path);
  const mergeAttributes = module.mergeAttributes ?? module.default.mergeAttributes;
  const result = mergeAttributes({ title: "normal" }, poison);
  assert.equal(result["data-poison-marker"] === "synthetic-poison", vulnerable);
  assert.equal(Object.getPrototypeOf(result) === Object.prototype, !vulnerable);
  assert.equal(mergeAttributes(null, { title: "normal" }).title, "normal");
  const ordinary = mergeAttributes(
    { class: "a b", style: "color: red; font-weight: bold" },
    { class: "b c", style: "color: blue", title: "kept" }
  );
  assert.equal(ordinary.class, "a b c");
  assert.equal(ordinary.style, "color: blue; font-weight: bold");
  assert.equal(ordinary.title, "kept");
  controls += 6;
}

const deepmerge = packageDirectory("deepmerge", "4.3.1");
for (const file of ["dist/cjs.js", "dist/umd.js"]) {
  const path = join(deepmerge, file);
  artifacts[`deepmerge/${file}`] = new Bun.CryptoHasher("sha256")
    .update(await Bun.file(path).arrayBuffer())
    .digest("hex");
  const module = await import(path);
  const merge = module.default;
  for (const [target, source] of [
    [Object.create(null), poison],
    [poison, {}],
  ]) {
    const result = merge(target, source);
    assert.equal(result["data-poison-marker"] === "synthetic-poison", vulnerable);
    assert.equal(Object.getPrototypeOf(result) === Object.prototype, !vulnerable);
    controls += 2;
  }
  assert.deepEqual(merge({ a: { x: 1 }, list: [1] }, { a: { y: 2 }, list: [2] }), { a: { x: 1, y: 2 }, list: [1, 2] });
  assert.deepEqual(merge.all([{ a: 1 }, { b: 2 }]), { a: 1, b: 2 });
  assert.deepEqual(merge({ list: [1] }, { list: [2] }, { arrayMerge: (_a: unknown, b: unknown) => b }), { list: [2] });
  const symbol = Symbol("ordinary fixture");
  assert.equal(merge({ [symbol]: 1 }, { b: 2 })[symbol], 1);
  const date = new Date(0);
  assert.equal(merge({ date }, {}).date, date);
  controls += 5;
}
assert.equal(({} as Record<string, unknown>)["data-poison-marker"], undefined, "No global prototype contamination");
controls += 1;
console.log(
  JSON.stringify({
    passed: true,
    mode,
    controls,
    bun: Bun.version,
    artifacts,
    limits: "Returned-object prototype controls; no claim that a browser XSS exploit was reproduced",
  })
);
