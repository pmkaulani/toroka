import os
os.environ["SSI_NO_AUTOAPP"] = "1"          # tests build their own app instance
os.environ["SSI_NO_WORKER"] = "1"           # tests do not start background worker daemon or touch manifest
import io
import pytest
from app.config import Settings
from app.main import create_app
from app.pipeline import Deps
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFont


class Env:
    def __init__(self, tmp_path, deps=None, senders=None, **kw):
        self.settings = Settings(database_url="sqlite://", storage_dir=str(tmp_path / "ev"), dev_echo_codes=True, public_base_url="https://ssi.test", **kw).with_dev_keys()
        self.app = create_app(self.settings, deps=deps or Deps(), senders=senders if senders is not None else {})
        self.client = TestClient(self.app)
        self.ctx = self.app.state.ctx

    def db(self):
        return self.ctx.sessionmaker()

    def check(self, text, headers=None, **extra):
        r = self.client.post("/v1/checks", json={"text": text, **extra}, headers=headers or {})
        assert r.status_code == 201, r.text
        return r.json()

    def user(self, email="ada@example.com", role="user"):
        r = self.client.post("/v1/auth/register", json={"email": email, "password": "correct horse battery"})
        assert r.status_code == 201, r.text
        if role != "user":
            from app import db as m
            with self.db() as db:
                u = db.get(m.User, r.json()["user_id"]); u.role = role; db.commit()
        return {"Authorization": "Bearer " + r.json()["token"]}, r.json()["user_id"]


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


@pytest.fixture
def make_env(tmp_path):
    def _make(**kw):
        return Env(tmp_path, **kw)
    return _make


def _font(size=44):
    for name in ["arial.ttf", "Arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "DejaVuSans.ttf"]:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            pass
    return ImageFont.load_default()


def png_with_text(text="Pay KSh 350 to activate funds", size=(900, 160)):
    img = Image.new("RGB", size, "white")
    ImageDraw.Draw(img).text((20, 50), text, fill="black", font=_font(44))
    b = io.BytesIO(); img.save(b, "PNG"); return b.getvalue()


def photo_like(seed, size=(480, 360)):
    import random
    r = random.Random(seed); img = Image.new("RGB", size, (r.randrange(256),) * 3); d = ImageDraw.Draw(img)
    for _ in range(40):
        x, y = r.randrange(size[0]), r.randrange(size[1])
        d.rectangle([x, y, x + r.randrange(40, 200), y + r.randrange(40, 160)], fill=tuple(r.randrange(256) for _ in range(3)))
    b = io.BytesIO(); img.save(b, "PNG"); return b.getvalue()
