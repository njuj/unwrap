"""Obfuscate, unwrap, demand the exact original back: every technique alone, then random stacks of them."""

import random
import unittest

import obfuscator as ob
from unwrap.engine import unwrap

STACKS = 300                                  # random stacks per language


class RoundTrip(unittest.TestCase):
    def assert_unwraps(self, code, payload, note):
        result = unwrap(code)
        self.assertEqual(result.final, payload, f"{note}\n--- input ---\n{code[:600]}\n--- stopped: {result.stopped}")

    def test_every_technique_alone(self):
        for lang, techniques in ob.TECHNIQUES.items():
            for technique in techniques:
                for i, payload in enumerate(ob.PAYLOADS[lang]):
                    for seed in range(8):
                        code = technique(random.Random(f"{i}/{seed}"), payload)
                        with self.subTest(technique=technique.__name__, payload=i, seed=seed):
                            self.assert_unwraps(code, payload, technique.__name__)

    def test_random_stacks(self):
        """2-5 layers, techniques picked at random: each layer's code becomes the next layer's payload."""
        for lang, techniques in ob.TECHNIQUES.items():
            for seed in range(STACKS):
                rng = random.Random(f"{lang}/{seed}")
                payload = rng.choice(ob.PAYLOADS[lang])
                code, used = ob.stack(rng, payload, techniques, rng.randint(2, 5))
                with self.subTest(lang=lang, seed=seed):
                    self.assert_unwraps(code, payload, " -> ".join(used))

    def test_layers_are_reported_in_order(self):
        payload = ob.PAYLOADS["powershell"][0]
        code = payload
        names = []
        for technique in (ob.ps_xor, ob.ps_gzip, ob.ps_base64, ob.ps_encoded):
            code = technique(random.Random(1), code)
            names.append(technique.__name__)
        result = unwrap(code)
        decoded = [layer.decoded_by.technique for layer in result.layers if layer.decoded_by]
        self.assertEqual(decoded[0], "encoded-command")
        self.assertEqual(decoded[-1], "xor")
        self.assertEqual(result.final, payload)

    def test_batch_launcher(self):
        for seed in range(40):
            rng = random.Random(seed)
            payload = rng.choice(ob.PAYLOADS["powershell"])
            inner, _ = ob.stack(rng, payload, ob.PS_TECHNIQUES, rng.randint(0, 3))
            with self.subTest(seed=seed):
                self.assert_unwraps(ob.batch_launcher(rng, inner), payload, "batch")

    def test_invoke_obfuscation_launchers(self):
        payload = ob.PAYLOADS["powershell"][0]
        for seed in range(200):
            rng = random.Random(seed)
            spelled = ob._iex_spelled(rng)
            for code in (f"&{spelled} ('{payload.replace(chr(39), chr(39) * 2)}')",
                         f"('{payload.replace(chr(39), chr(39) * 2)}') | .{spelled}"):
                with self.subTest(code=code):
                    self.assert_unwraps(code, payload, "launcher")


if __name__ == "__main__":
    unittest.main()
