# 08 Docs and release v0.1.0 — DEV checks

README commands, install from a clean venv, tests (559 passed, 85.7 % coverage) and lint were checked by the AI. These need GitHub or a human decision.

- [x] 🖱️ Push `main` and tag `v0.1.0` (`git push origin main v0.1.0`); tag is created locally, not pushed
- [x] 🖱️ Create the GitHub release `v0.1.0` with the CHANGELOG 0.1.0 section as notes (`gh release create v0.1.0 --notes-file ...`)
- [ ] 🖱️ On GitHub (repo public): README renders, the Mermaid diagram shows, `docs/demo.svg` displays, every link works
- [ ] 🖱️ Replace `docs/demo.svg` by a recorded GIF if wanted (the SVG is a rendered capture, not a recording)
- [ ] 🖱️ `pipx install git+https://github.com/Nakken13/secrety` works from the pushed repo and `secrety --version` prints 0.1.0
