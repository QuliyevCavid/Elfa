import os
import json
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SESSION_DAYS = 14

app = FastAPI(title="ELFA API")


@contextmanager
def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable təyin edilməyib.")
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def hash_password(password: str, salt: str | None = None):
    salt = salt or secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), 200_000
    ).hex()
    return salt, hashed


def verify_password(password: str, salt: str, expected: str) -> bool:
    _, actual = hash_password(password, salt)
    return hmac.compare_digest(actual, expected)


def make_session(seller_id: int) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO public.sessions
                (token_hash, seller_id, expires_at, created_at)
            VALUES (%s, %s, %s, %s)
            """,
            (token_hash, seller_id, now + timedelta(days=SESSION_DAYS), now),
        )
    return token


def get_seller(authorization: str | None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Giriş tələb olunur")

    token = authorization.split(" ", 1)[1].strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with db() as conn:
        row = conn.execute(
            """
            SELECT s.*
            FROM public.sessions se
            JOIN public.sellers s ON s.id = se.seller_id
            WHERE se.token_hash = %s AND se.expires_at > %s
            """,
            (token_hash, datetime.now(timezone.utc)),
        ).fetchone()

    if not row:
        raise HTTPException(401, "Sessiya bitib. Yenidən daxil olun.")
    return row


def require_admin(token: str | None):
    if not ADMIN_TOKEN or not token or not hmac.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(403, "Admin icazəsi yoxdur")


def clean_seller(row):
    if not row:
        return None
    result = dict(row)
    for key in ("password_hash", "pw_hash", "pw_salt"):
        result.pop(key, None)
    return result


def clean_product(row):
    if not row:
        return None
    result = dict(row)
    result["images"] = result.get("images") or []
    result["sizes"] = result.get("sizes") or []
    return result


def parse_json_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (ValueError, TypeError):
            return [x.strip() for x in value.split(",") if x.strip()]
    return []


class SellerRegister(BaseModel):
    store_name: str
    owner_name: str
    email: str
    phone: str
    password: str = Field(min_length=6)
    whatsapp: str | None = None
    city: str | None = None
    address: str | None = None
    category: str | None = None
    about: str | None = None
    logo_url: str | None = None
    instagram: str | None = None
    tiktok: str | None = None


class SellerLogin(BaseModel):
    email: str
    password: str


class SellerProfile(BaseModel):
    store_name: str | None = None
    owner_name: str | None = None
    phone: str | None = None
    whatsapp: str | None = None
    city: str | None = None
    address: str | None = None
    about: str | None = None
    logo_url: str | None = None
    instagram: str | None = None
    tiktok: str | None = None


class ProductInput(BaseModel):
    name: str
    price: float = Field(ge=0)
    stock: int = Field(default=0, ge=0)
    image_url: str | None = None
    images: list = Field(default_factory=list)
    video_url: str | None = None
    description: str | None = None
    category: str | None = None
    brand: str | None = None
    gender: str | None = None
    age_group: str | None = None
    sizes: list = Field(default_factory=list)
    color: str | None = None
    size_class: str | None = None
    dimensions: str | None = None
    material: str | None = None


@app.get("/api/health")
def health():
    with db() as conn:
        conn.execute("SELECT 1")
    return {"ok": True, "database": "connected"}


# -------------------- SATICI QEYDIYYATI VƏ GİRİŞ --------------------

@app.post("/api/sellers/register")
def register_seller(data: SellerRegister):
    salt, password_hash = hash_password(data.password)
    now = datetime.now(timezone.utc)

    with db() as conn:
        exists = conn.execute(
            "SELECT id FROM public.sellers WHERE lower(email) = lower(%s)",
            (data.email.strip(),),
        ).fetchone()

        if exists:
            raise HTTPException(409, "Bu e-poçt artıq qeydiyyatdan keçib")

        seller = conn.execute(
            """
            INSERT INTO public.sellers
            (
                store_name, owner_name, email, phone, whatsapp,
                city, address, category, about, logo_url,
                instagram, tiktok, password_hash, pw_salt, pw_hash,
                status, created_at, home_used
            )
            VALUES
            (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
             %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                data.store_name.strip(),
                data.owner_name.strip(),
                data.email.strip().lower(),
                data.phone.strip(),
                data.whatsapp,
                data.city,
                data.address,
                data.category,
                data.about,
                data.logo_url,
                data.instagram,
                data.tiktok,
                password_hash,
                salt,
                password_hash,
                "pending",
                now,
                0,
            ),
        ).fetchone()

    return {"ok": True, "seller": clean_seller(seller)}


@app.post("/api/sellers/login")
def login_seller(data: SellerLogin):
    with db() as conn:
        seller = conn.execute(
            "SELECT * FROM public.sellers WHERE lower(email) = lower(%s)",
            (data.email.strip(),),
        ).fetchone()

    if not seller:
        raise HTTPException(401, "E-poçt və ya şifrə yanlışdır")

    salt = seller.get("pw_salt")
    expected = seller.get("pw_hash") or seller.get("password_hash")

    if not salt or not expected or not verify_password(
        data.password, salt, expected
    ):
        raise HTTPException(401, "E-poçt və ya şifrə yanlışdır")

    token = make_session(seller["id"])
    return {
        "ok": True,
        "token": token,
        "seller": clean_seller(seller),
    }


@app.post("/api/seller/logout")
def logout_seller(authorization: str | None = Header(default=None)):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with db() as conn:
            conn.execute(
                "DELETE FROM public.sessions WHERE token_hash = %s",
                (token_hash,),
            )
    return {"ok": True}


@app.get("/api/seller/me")
def seller_me(authorization: str | None = Header(default=None)):
    return {"seller": clean_seller(get_seller(authorization))}


@app.put("/api/seller/profile")
def update_profile(
    data: SellerProfile,
    authorization: str | None = Header(default=None),
):
    seller = get_seller(authorization)
    fields = data.model_dump(exclude_unset=True)

    if not fields:
        return {"ok": True, "seller": clean_seller(seller)}

    allowed = {
        "store_name", "owner_name", "phone", "whatsapp", "city",
        "address", "about", "logo_url", "instagram", "tiktok",
    }
    fields = {k: v for k, v in fields.items() if k in allowed}

    with db() as conn:
        updated = conn.execute(
            """
            UPDATE public.sellers
            SET store_name = COALESCE(%s, store_name),
                owner_name = COALESCE(%s, owner_name),
                phone = COALESCE(%s, phone),
                whatsapp = COALESCE(%s, whatsapp),
                city = COALESCE(%s, city),
                address = COALESCE(%s, address),
                about = COALESCE(%s, about),
                logo_url = COALESCE(%s, logo_url),
                instagram = COALESCE(%s, instagram),
                tiktok = COALESCE(%s, tiktok)
            WHERE id = %s
            RETURNING *
            """,
            (
                fields.get("store_name"), fields.get("owner_name"),
                fields.get("phone"), fields.get("whatsapp"),
                fields.get("city"), fields.get("address"),
                fields.get("about"), fields.get("logo_url"),
                fields.get("instagram"), fields.get("tiktok"),
                seller["id"],
            ),
        ).fetchone()

    return {"ok": True, "seller": clean_seller(updated)}


# -------------------- ŞƏKİL YÜKLƏMƏ --------------------

@app.post("/api/seller/upload")
async def upload_image(
    file=None,
    authorization: str | None = Header(default=None),
):
    # Fayl yükləməsi üçün aşağıda göstərilən multipart/form-data
    # düzəlişini ayrıca tətbiq etmək lazımdır.
    raise HTTPException(
        501,
        "Şəkil yükləmə endpoint-i mövcud HTML forması ilə uyğunlaşdırılmalıdır",
    )


@app.get("/api/images/{iid}")
def get_image(iid: int):
    with db() as conn:
        row = conn.execute(
            "SELECT mime, data FROM public.images WHERE id = %s",
            (iid,),
        ).fetchone()

    if not row:
        raise HTTPException(404, "Şəkil tapılmadı")

    return Response(
        content=bytes(row["data"]),
        media_type=row["mime"],
        headers={"Cache-Control": "public, max-age=86400"},
    )


# -------------------- MƏHSULLAR --------------------

@app.get("/api/seller/products")
def seller_products(authorization: str | None = Header(default=None)):
    seller = get_seller(authorization)
    with db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM public.products
            WHERE seller_id = %s
            ORDER BY created_at DESC, id DESC
            """,
            (seller["id"],),
        ).fetchall()
    return {"products": [clean_product(x) for x in rows]}


@app.post("/api/seller/products")
def add_product(
    data: ProductInput,
    authorization: str | None = Header(default=None),
):
    seller = get_seller(authorization)
    now = datetime.now(timezone.utc)
    images = data.images or ([data.image_url] if data.image_url else [])

    with db() as conn:
        row = conn.execute(
            """
            INSERT INTO public.products
            (
                seller_id, name, price, stock, image_url, images,
                video_url, description, category, brand, gender,
                age_group, sizes, color, size_class, dimensions,
                material, on_home, created_at
            )
            VALUES
            (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
             %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                seller["id"], data.name, data.price, data.stock,
                data.image_url, Jsonb(images), data.video_url,
                data.description, data.category, data.brand,
                data.gender, data.age_group, Jsonb(data.sizes),
                data.color, data.size_class, data.dimensions,
                data.material, False, now,
            ),
        ).fetchone()

    return {"ok": True, "product": clean_product(row)}


@app.put("/api/seller/products/{pid}")
def edit_product(
    pid: int,
    data: ProductInput,
    authorization: str | None = Header(default=None),
):
    seller = get_seller(authorization)
    values = data.model_dump()
    images = values["images"] or (
        [values["image_url"]] if values["image_url"] else []
    )

    with db() as conn:
        row = conn.execute(
            """
            UPDATE public.products SET
                name = %s, price = %s, stock = %s, image_url = %s,
                images = %s, video_url = %s, description = %s,
                category = %s, brand = %s, gender = %s,
                age_group = %s, sizes = %s, color = %s,
                size_class = %s, dimensions = %s, material = %s
            WHERE id = %s AND seller_id = %s
            RETURNING *
            """,
            (
                values["name"], values["price"], values["stock"],
                values["image_url"], Jsonb(images), values["video_url"],
                values["description"], values["category"], values["brand"],
                values["gender"], values["age_group"], Jsonb(values["sizes"]),
                values["color"], values["size_class"], values["dimensions"],
                values["material"], pid, seller["id"],
            ),
        ).fetchone()

    if not row:
        raise HTTPException(404, "Məhsul tapılmadı")
    return {"ok": True, "product": clean_product(row)}


@app.delete("/api/seller/products/{pid}")
def delete_product(
    pid: int,
    authorization: str | None = Header(default=None),
):
    seller = get_seller(authorization)
    with db() as conn:
        result = conn.execute(
            "DELETE FROM public.products WHERE id = %s AND seller_id = %s",
            (pid, seller["id"]),
        )
        if result.rowcount == 0:
            raise HTTPException(404, "Məhsul tapılmadı")
    return {"ok": True}


@app.put("/api/seller/products/{pid}/home")
def seller_product_home(
    pid: int,
    authorization: str | None = Header(default=None),
):
    seller = get_seller(authorization)
    with db() as conn:
        row = conn.execute(
            """
            UPDATE public.products SET on_home = NOT on_home
            WHERE id = %s AND seller_id = %s
            RETURNING *
            """,
            (pid, seller["id"]),
        ).fetchone()

    if not row:
        raise HTTPException(404, "Məhsul tapılmadı")
    return {"ok": True, "product": clean_product(row)}


# -------------------- AÇIQ MƏHSUL VƏ MAĞAZA SƏHİFƏLƏRİ --------------------

@app.get("/api/products")
def public_products(
    category: str | None = None,
    gender: str | None = None,
    search: str | None = None,
    sort: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    conditions = ["s.status = 'approved'"]
    params = []

    if category:
        conditions.append("p.category = %s")
        params.append(category)
    if gender:
        conditions.append("p.gender = %s")
        params.append(gender)
    if search:
        conditions.append("(p.name ILIKE %s OR p.description ILIKE %s)")
        params.extend([f"%{search}%", f"%{search}%"])

    order = "p.created_at DESC, p.id DESC"
    if sort == "price_asc":
        order = "p.price ASC, p.id DESC"
    elif sort == "price_desc":
        order = "p.price DESC, p.id DESC"

    sql = f"""
        SELECT p.*, s.store_name, s.logo_url AS store_logo
        FROM public.products p
        JOIN public.sellers s ON s.id = p.seller_id
        WHERE {" AND ".join(conditions)}
        ORDER BY {order}
        LIMIT %s OFFSET %s
    """
    params.extend([limit, offset])

    with db() as conn:
        rows = conn.execute(sql, params).fetchall()

    return {"products": [clean_product(x) for x in rows]}


@app.get("/api/products/{pid}")
def public_product(pid: int):
    with db() as conn:
        row = conn.execute(
            """
            SELECT p.*, s.store_name, s.logo_url AS store_logo,
                   s.city AS store_city
            FROM public.products p
            JOIN public.sellers s ON s.id = p.seller_id
            WHERE p.id = %s AND s.status = 'approved'
            """,
            (pid,),
        ).fetchone()

    if not row:
        raise HTTPException(404, "Məhsul tapılmadı")
    return {"product": clean_product(row)}


@app.get("/api/stores")
def public_stores(
    search: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    with db() as conn:
        if search:
            rows = conn.execute(
                """
                SELECT id, store_name, city, address, phone, image,
                       logo_url, about, created_at
                FROM public.sellers
                WHERE status = 'approved'
                  AND (store_name ILIKE %s OR city ILIKE %s)
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (f"%{search}%", f"%{search}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, store_name, city, address, phone, image,
                       logo_url, about, created_at
                FROM public.sellers
                WHERE status = 'approved'
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            ).fetchall()

    return {"stores": [dict(x) for x in rows]}


@app.get("/api/stores/{sid}")
def public_store(sid: int):
    with db() as conn:
        store = conn.execute(
            """
            SELECT id, store_name, owner_name, city, address, phone,
                   whatsapp, about, logo_url, instagram, tiktok, created_at
            FROM public.sellers
            WHERE id = %s AND status = 'approved'
            """,
            (sid,),
        ).fetchone()

        if not store:
            raise HTTPException(404, "Mağaza tapılmadı")

        products = conn.execute(
            """
            SELECT * FROM public.products
            WHERE seller_id = %s
            ORDER BY created_at DESC
            """,
            (sid,),
        ).fetchall()

    return {
        "store": dict(store),
        "products": [clean_product(x) for x in products],
    }


@app.get("/api/options")
def options():
    with db() as conn:
        categories = conn.execute(
            """
            SELECT DISTINCT category FROM public.products
            WHERE category IS NOT NULL AND category <> ''
            ORDER BY category
            """
        ).fetchall()
        genders = conn.execute(
            """
            SELECT DISTINCT gender FROM public.products
            WHERE gender IS NOT NULL AND gender <> ''
            ORDER BY gender
            """
        ).fetchall()

    return {
        "categories": [x["category"] for x in categories],
        "genders": [x["gender"] for x in genders],
    }


@app.get("/api/filters")
def filters():
    return options()


# -------------------- ADMIN --------------------

@app.get("/api/admin/sellers")
def admin_sellers(
    x_admin_token: str | None = Header(default=None),
):
    require_admin(x_admin_token)
    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, store_name, owner_name, email, phone, whatsapp,
                   city, address, category, about, logo_url, instagram,
                   tiktok, status, created_at, home_used
            FROM public.sellers
            ORDER BY created_at DESC
            """
        ).fetchall()
    return {"sellers": [dict(x) for x in rows]}


class SellerStatus(BaseModel):
    status: str


@app.post("/api/admin/sellers/{sid}/status")
def admin_seller_status(
    sid: int,
    data: SellerStatus,
    x_admin_token: str | None = Header(default=None),
):
    require_admin(x_admin_token)
    if data.status not in {"pending", "approved", "rejected"}:
        raise HTTPException(400, "Status düzgün deyil")

    with db() as conn:
        row = conn.execute(
            """
            UPDATE public.sellers SET status = %s
            WHERE id = %s RETURNING id, store_name, status
            """,
            (data.status, sid),
        ).fetchone()

    if not row:
        raise HTTPException(404, "Satıcı tapılmadı")
    return {"ok": True, "seller": dict(row)}


@app.get("/api/admin/products")
def admin_products(
    x_admin_token: str | None = Header(default=None),
):
    require_admin(x_admin_token)
    with db() as conn:
        rows = conn.execute(
            """
            SELECT p.*, s.store_name
            FROM public.products p
            LEFT JOIN public.sellers s ON s.id = p.seller_id
            ORDER BY p.created_at DESC
            """
        ).fetchall()
    return {"products": [clean_product(x) for x in rows]}


@app.post("/api/admin/products/{pid}/home")
def admin_product_home(
    pid: int,
    x_admin_token: str | None = Header(default=None),
):
    require_admin(x_admin_token)
    with db() as conn:
        row = conn.execute(
            """
            UPDATE public.products SET on_home = NOT on_home
            WHERE id = %s RETURNING *
            """,
            (pid,),
        ).fetchone()

    if not row:
        raise HTTPException(404, "Məhsul tapılmadı")
    return {"ok": True, "product": clean_product(row)}


@app.post("/api/admin/sellers/{sid}/home")
def admin_seller_home(
    sid: int,
    x_admin_token: str | None = Header(default=None),
):
    require_admin(x_admin_token)
    with db() as conn:
        row = conn.execute(
            """
            UPDATE public.sellers SET home_used = CASE
                WHEN home_used > 0 THEN 0 ELSE 1 END
            WHERE id = %s RETURNING id, store_name, home_used
            """,
            (sid,),
        ).fetchone()

    if not row:
        raise HTTPException(404, "Satıcı tapılmadı")
    return {"ok": True, "seller": dict(row)}


@app.delete("/api/admin/products/{pid}")
def admin_delete_product(
    pid: int,
    x_admin_token: str | None = Header(default=None),
):
    require_admin(x_admin_token)
    with db() as conn:
        result = conn.execute(
            "DELETE FROM public.products WHERE id = %s",
            (pid,),
        )
        if result.rowcount == 0:
            raise HTTPException(404, "Məhsul tapılmadı")
    return {"ok": True}


# -------------------- HTML SƏHİFƏLƏRİ --------------------

@app.get("/")
def homepage():
    path = BASE_DIR / "index.html"
    if not path.exists():
        raise HTTPException(404, "index.html tapılmadı")
    return FileResponse(path)


@app.get("/elfa.html")
def elfa_page():
    path = BASE_DIR / "index.html"
    if not path.exists():
        raise HTTPException(404, "index.html tapılmadı")
    return FileResponse(path)


@app.get("/admin")
def admin_page():
    path = BASE_DIR / "admin.html"
    if not path.exists():
        raise HTTPException(404, "admin.html tapılmadı")
    return FileResponse(path)


@app.get("/seller-register.html")
def seller_register_page():
    path = BASE_DIR / "seller-register.html"
    if not path.exists():
        raise HTTPException(404, "seller-register.html tapılmadı")
    return FileResponse(path)


if (BASE_DIR / "static").is_dir():
    app.mount(
        "/static",
        StaticFiles(directory=str(BASE_DIR / "static")),
        name="static",
    )