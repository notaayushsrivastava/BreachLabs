# BreachLabs Website

Marketing + product-narrative site. Flask + Jinja + Tailwind CDN + vanilla JS.
Isolated to `website/` — never modify `breachlabs/` core from here.

## Run

```bash
cd website
pip install -r requirements.txt
flask --app app run
# or: python app.py
```

## Test

```bash
pytest website/tests -q
```

## Notes

- Tailwind via CDN (no build step in v1).
- Demo is static + illustrative (`DEMO-0001`). No `/api/*`, no live scanning.
- Future core wiring point: `get_demo_assessment()` in `app.py`.
