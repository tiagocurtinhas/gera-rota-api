# gen_flask_from_json.py
# -*- coding: utf-8 -*-
"""
Gera arquivos Flask (entity/model/schema/service/view-RESTful) a partir de um JSON de entidade.

Uso:
    python gen_flask_from_json.py --input entidade.json --outdir .

Projeto-alvo deve possuir:
    - extensions.py     -> expõe db (SQLAlchemy) e ma (Marshmallow)
    - api.py            -> expõe api = Api(app) do Flask-RESTful
    - Flask-JWT-Extended configurado (para @jwt_required)
    - Pasta 'static/files' (o script cria se não existir)

Principais recursos:
    - 'nome_tabela' no JSON para fixar __tablename__
    - Campos 'str' podem ter 'tam' para db.String(tam) e validate.Length(max=tam)
    - Campos 'file': upload em static/files, download via Flask-RESTful e <campo>_url na resposta
    - Entidade gerada como classe encapsulada (atributos privados + @property/@setter)
    - Se 'senha': true no JSON, gera rotas extras de autenticação (login/reset/ativação/refresh etc.)
"""

import argparse
import json
import os
import re
import textwrap
from pathlib import Path

# ---------- helpers básicos ----------

def to_snake(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    s2 = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1)
    return s2.replace("-", "_").lower()

def to_plural(singular: str) -> str:
    s = singular.lower()
    if s.endswith("y") and not s.endswith(("ay","ey","iy","oy","uy")):
        return s[:-1] + "ies"
    if s.endswith("s"):
        return s + "es"
    return s + "s"

def indent(code: str, spaces=4) -> str:
    return textwrap.indent(code, " " * spaces)

def ensure_dirs(outdir: Path):
    (outdir / "static" / "files").mkdir(parents=True, exist_ok=True)

def map_sqla_type(campo):
    t = campo["tipo"].lower()
    if t == "str":
        tam = int(campo.get("tam", 255))
        return f"db.String({tam})"
    if t == "text":
        return "db.Text"
    if t == "int":
        return "db.Integer"
    if t == "float":
        return "db.Float"
    if t == "bool":
        return "db.Boolean"
    if t == "datetime":
        return "db.DateTime"
    if t == "date":
        return "db.Date"
    if t == "uuid":
        return "db.String(36)"
    if t == "file":
        return "db.String(255)"  # armazena o nome do arquivo salvo
    return "db.String(255)"

def map_marshmallow_field(campo):
    t = campo["tipo"].lower()
    mm = {
        "str": "fields.String",
        "text": "fields.String",
        "int": "fields.Integer",
        "float": "fields.Float",
        "bool": "fields.Boolean",
        "datetime": "fields.DateTime",
        "date": "fields.Date",
        "uuid": "fields.UUID",
        "file": "fields.String",
    }
    return mm.get(t, "fields.String")

def default_py_value(campo):
    if "default" not in campo:
        return None
    d = campo["default"]
    t = campo["tipo"].lower()
    if t in ("int","float"):
        try:
            _ = float(d) if t == "float" else int(d)
            return str(d)
        except Exception:
            pass
    if t == "bool":
        return "True" if str(d).lower() in ("true","1","yes","sim") else "False"
    if t in ("datetime","date") and str(d).lower() == "now":
        return "func.now()" if t == "datetime" else "date.today"
    return repr(d)

def build_sqla_column(campo):
    parts = [map_sqla_type(campo)]
    if campo.get("primary_key"):
        parts.append("primary_key=True")
    if campo.get("autoincrement"):
        parts.append("autoincrement=True")
    if campo.get("unico"):
        parts.append("unique=True")
    if campo.get("obrigatorio"):
        parts.append("nullable=False")
    d = default_py_value(campo)
    if d:
        if d in ("datetime.utcnow", "date.today"):
            parts.append(f"default={d}")
        else:
            parts.append(f"default={d}")
    return f"db.Column({', '.join(parts)})"

def file_fields(campos):
    return [c["nome"] for c in campos if c["tipo"].lower() == "file"]

# ---------- templates ----------

# ENTIDADE ENCAPSULADA (atributos privados + properties)
ENTITY_TMPL = '''"""Entidade de domínio (encapsulada) para %%ClassName%%.
Atributos privados (__campo) com acesso via @property/@setter.
Inclui validações básicas: obrigatoriedade, tipo e tamanho máximo (str).
"""
from datetime import datetime, date

class %%ClassName%%Entity:
    def __init__(self, %%init_params%%):
%%init_body%%

%%properties%%
'''

MODEL_TMPL = '''"""Modelo SQLAlchemy para %%ClassName%%."""
from api import db  
from sqlalchemy.sql import func

class %%ClassName%%(db.Model):
    __tablename__ = "%%table_name%%"

%%columns%%

    def __repr__(self):
        return f"<%%ClassName%% id={self.%%id_field%%}>"
'''

SCHEMA_TMPL = '''"""Schema Marshmallow para %%ClassName%%."""
from marshmallow import fields, validate
from api import ma  # ajuste o import conforme seu projeto
from ..models.%%module_model%% import %%ClassName%%

class %%ClassName%%Schema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = %%ClassName%%
        load_instance = True
        fields=(%%init_params%%)

%%fields%%
'''

SERVICE_TMPL = '''"""Serviço (regras de negócio) para %%ClassName%%."""
import os
import uuid
from werkzeug.utils import secure_filename
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timedelta
from api import db
from sqlalchemy.sql import func, text
from ..models.%%module_model%% import %%ClassName%%
from ..schemas.%%module_schema%% import %%ClassName%%Schema

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "files")

# ---- Ajuste estes nomes conforme seus campos/colunas ----
EMAIL_FIELD = "no_email"
PASSWORD_FIELD = "no_password"
CODE_FIELD = "co_validate"
UPDATED_AT_FIELD = "dt_update"
ACTIVE_FIELD = "ic_ativo"
IS_ACTIVATED_FIELD = "is_activated"  # opcional
IS_BLOCKED_FIELD = "is_blocked"      # opcional
CODE_EXP_MINUTES = 30  # validade do código de verificação em minutos
# ---------------------------------------------------------

schema = %%ClassName%%Schema()
schema_many = %%ClassName%%Schema(many=True)

def _save_file(fs_storage):
    """
    Salva um arquivo de upload em static/files e retorna o nome salvo.
    """
    if not fs_storage:
        return None
    filename = secure_filename(fs_storage.filename or "")
    if not filename:
        return None
    root, ext = os.path.splitext(filename)
    new_name = f"{uuid.uuid4().hex}{ext.lower()}"
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    fs_storage.save(os.path.join(UPLOAD_DIR, new_name))
    return new_name

def _augment_file_urls(obj_dict):
    %%file_url_augment%%

def create(data, files=None):
    files = files or {}
    %%file_assign_create%%
    obj = schema.load(data, session=db.session)
    db.session.add(obj)
    db.session.commit()
    result = schema.dump(obj)
    _augment_file_urls(result)
    return result

def list_all():
    objs = %%ClassName%%.query.order_by(%%ClassName%%.%%order_field%%.desc() if hasattr(%%ClassName%%, "%%order_field%%") else %%ClassName%%.%%id_field%%.desc()).all()
    result = schema_many.dump(objs)
    for r in result:
        _augment_file_urls(r)
    return result

def get_by_id(obj_id):
    obj = %%ClassName%%.query.get_or_404(obj_id)
    result = schema.dump(obj)
    _augment_file_urls(result)
    return result

def update(obj_id, data, files=None):
    files = files or {}
    obj = %%ClassName%%.query.get_or_404(obj_id)
    %%file_assign_update%%
    for k, v in data.items():
        setattr(obj, k, v)
    db.session.commit()
    result = schema.dump(obj)
    _augment_file_urls(result)
    return result

def delete(obj_id):
    obj = %%ClassName%%.query.get_or_404(obj_id)
    db.session.delete(obj)
    db.session.commit()
    return {"deleted": True}

# ----------------- AUXÍLIOS PARA AUTENTICAÇÃO -----------------

def _now():
    return datetime.now()

def generate_numeric_code(n=6):
    """Gera um código numérico com n dígitos (ex.: 6 -> 000000..999999)"""
    return str(uuid.uuid4().int)[0:n]

def send_email_html(to_email: str, subject: str, html: str):
    """
    GANCHO de e-mail: implemente com seu serviço (SMTP/SendGrid/etc).
    Ex.: import your_mailer; your_mailer.send(to_email, subject, html)
    """
    # raise NotImplementedError("Conecte aqui seu serviço de e-mail.")
    return True

def hash_password(plain: str) -> str:
    return pbkdf2_sha256.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pbkdf2_sha256.verify(plain, hashed)
    except Exception:
        return False

def find_by_email(email: str):
    fld = getattr(%%ClassName%%, EMAIL_FIELD, None)
    if not fld:
        return None
    return %%ClassName%%.query.filter(fld == email).first()

def set_code_and_touch(user, code: str):
    if hasattr(user, CODE_FIELD):
        setattr(user, CODE_FIELD, code)
    if hasattr(user, UPDATED_AT_FIELD):
        setattr(user, UPDATED_AT_FIELD, _now())
    db.session.commit()

def code_is_valid(user, code: str) -> bool:
    if not hasattr(user, CODE_FIELD):
        return False
    user_code = getattr(user, CODE_FIELD)
    if not user_code or str(user_code) != str(code):
        return False
    # validade temporal
    if hasattr(user, UPDATED_AT_FIELD):
        dt = getattr(user, UPDATED_AT_FIELD)
        if not dt:
            return False
        return (_now() - dt) <= timedelta(minutes=CODE_EXP_MINUTES)
    return True  # se não tem UPDATED_AT_FIELD, só igualdade do código

def activate_user(user):
    if hasattr(user, ACTIVE_FIELD):
        setattr(user, ACTIVE_FIELD, 1)
    if hasattr(user, IS_ACTIVATED_FIELD):
        setattr(user, IS_ACTIVATED_FIELD, 1)
    db.session.commit()

def soft_blocked_or_inactive(user) -> bool:
    if hasattr(user, IS_BLOCKED_FIELD) and getattr(user, IS_BLOCKED_FIELD):
        return True
    if hasattr(user, ACTIVE_FIELD) and not getattr(user, ACTIVE_FIELD):
        return True
    return False
'''

# VIEW no padrão Flask-RESTful (CRUD)
VIEW_RESTFUL_TMPL = '''"""Resources Flask-RESTful para %%ClassName%% (CRUD)."""
import os
from flask import request, make_response, jsonify, send_from_directory
from flask_restful import Resource
from flask_jwt_extended import jwt_required
from api import api  # ajuste o import conforme seu projeto

from %%module_schema%% import %%ClassName%%Schema
from %%module_service%% import create, list_all, get_by_id, update, delete, UPLOAD_DIR
from %%module_model%% import %%ClassName%%

ps_single = %%ClassName%%Schema()
ps_many = %%ClassName%%Schema(many=True)

class %%ClassName%%List(Resource):
    @jwt_required()
    def get(self):
        data = list_all()
        return make_response(ps_many.jsonify(data), 200)

    @jwt_required()
    def post(self):
        # aceita JSON ou multipart/form-data
        data = dict(request.form) if request.form else (request.json or {})
        files = request.files if request.files else {}
        try:
            result = create(data, files)
        except Exception as e:
            return make_response(jsonify({'message': str(e)}), 400)
        return make_response(ps_single.jsonify(result), 201)

class %%ClassName%%Detail(Resource):
    @jwt_required()
    def get(self, id):
        try:
            data = get_by_id(id)
        except Exception:
            return make_response(jsonify('recurso não encontrado'), 404)
        return make_response(ps_single.jsonify(data), 200)

    @jwt_required()
    def put(self, id):
        data = dict(request.form) if request.form else (request.json or {})
        files = request.files if request.files else {}
        try:
            result = update(id, data, files)
        except Exception as e:
            return make_response(jsonify({'message': str(e)}), 400)
        return make_response(ps_single.jsonify(result), 200)

    @jwt_required()
    def patch(self, id):
        return self.put(id)

    @jwt_required()
    def delete(self, id):
        try:
            delete(id)
        except Exception:
            return make_response(jsonify('recurso não encontrado'), 404)
        return make_response('', 204)

%%file_download_resources%%

# registrando as rotas
api.add_resource(%%ClassName%%List, '/%%plural%%')
api.add_resource(%%ClassName%%Detail, '/%%plural%%/<int:id>')
%%add_resource_downloads%%
'''

# VIEW de autenticação/segurança (gerada quando "senha": true)
AUTH_VIEW_TMPL = '''"""Resources de autenticação/segurança para %%ClassName%%."""
from flask import request, make_response, jsonify
from flask_restful import Resource
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from datetime import timedelta
from api import api

from %%module_schema%% import %%ClassName%%Schema
from %%module_model%% import %%ClassName%%
from %%module_service%% import (
    find_by_email, verify_password, hash_password, generate_numeric_code,
    set_code_and_touch, code_is_valid, activate_user, soft_blocked_or_inactive,
    EMAIL_FIELD, PASSWORD_FIELD, CODE_FIELD, ACTIVE_FIELD
)

ps_single = %%ClassName%%Schema()

class %%ClassName%%Login(Resource):
    def post(self):
        data = request.json or {}
        if 'no_email' not in data or 'no_password' not in data:
            return make_response({'message': 'Campos no_email e no_password são obrigatórios'}, 400)
        user = find_by_email(data['no_email'])
        if not user:
            return make_response({'erro': True, 'message': 'Usuário não encontrado', 'dados': None}, 404)
        if soft_blocked_or_inactive(user):
            return make_response({'erro': True, 'message': 'Usuário inativo/bloqueado', 'dados': None}, 400)
        pwd_ok = verify_password(data['no_password'], getattr(user, PASSWORD_FIELD, '') or '')
        if not pwd_ok:
            return make_response({'erro': True, 'message': 'Credenciais inválidas', 'dados': None}, 400)

        access_token = create_access_token(identity=str(getattr(user, 'id', getattr(user, 'co_user', 0))), expires_delta=timedelta(seconds=82400), fresh=True)
        refresh_token = create_refresh_token(identity=str(getattr(user, 'id', getattr(user, 'co_user', 0))))

        # opcional: salvar token em CODE_FIELD
        if hasattr(user, CODE_FIELD):
            setattr(user, CODE_FIELD, access_token)
        # carimbar atualização
        if hasattr(user, 'dt_update'):
            from %%module_service%% import _now, db
            setattr(user, 'dt_update', _now())
            db.session.commit()

        payload = ps_single.dump(user)
        return make_response({'dados': payload, 'access_token': access_token, 'refresh_token': refresh_token}, 200)

class %%ClassName%%Refresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity, fresh=False)
        return jsonify(access_token=access_token)

class %%ClassName%%SendCode(Resource):
    """
    Envia código por e-mail para ativação de conta ou reset de senha.
    body: { "no_email": "a@b.com", "contexto": "ativacao"|"reset" }
    """
    def put(self):
        data = request.json or {}
        email = data.get('no_email')
        if not email:
            return make_response({'erro': True, 'message': 'Email não informado', 'dados': None}, 400)
        user = find_by_email(email)
        if not user:
            return make_response({'erro': True, 'message': 'Usuário não encontrado', 'dados': None}, 404)
        code = generate_numeric_code(6)
        set_code_and_touch(user, code)

        # Enviar e-mail (HTML simples). Substitua por seu template.
        from %%module_service%% import send_email_html
        assunto = 'Código de validação'
        html = f"<p>Olá {getattr(user, 'no_user', '')}, seu código é <b>{code}</b>. Ele expira em breve.</p>"
        send_email_html(email, assunto, html)

        return make_response({'erro': False, 'message': 'Código enviado para o e-mail informado'}, 200)

class %%ClassName%%ValidateCode(Resource):
    """
    Valida um código recebido por e-mail.
    body: { "no_email": "a@b.com", "co_validate": "123456" }
    """
    def post(self):
        data = request.json or {}
        email = data.get('no_email')
        code = data.get('co_validate')
        if not email or not code:
            return make_response({'erro': True, 'message': 'no_email e co_validate são obrigatórios', 'dados': None}, 400)
        user = find_by_email(email)
        if not user:
            return make_response({'erro': True, 'message': 'Usuário não encontrado', 'dados': None}, 404)
        if not code_is_valid(user, code):
            return make_response({'erro': True, 'message': 'Código inválido ou expirado', 'dados': None}, 400)
        # sucesso: ativar conta (ic_ativo=1) se fizer sentido
        if hasattr(user, ACTIVE_FIELD):
            activate_user(user)
        return make_response({'erro': False, 'message': 'Código validado com sucesso'}, 200)

class %%ClassName%%ResetPassword(Resource):
    """
    Redefine a senha usando um código válido.
    body: { "no_email": "a@b.com", "co_validate": "123456", "no_password": "novaSenha" }
    """
    def put(self):
        data = request.json or {}
        email = data.get('no_email')
        code = data.get('co_validate')
        new_pwd = data.get('no_password')
        if not email or not code or not new_pwd:
            return make_response({'erro': True, 'message': 'no_email, co_validate e no_password são obrigatórios', 'dados': None}, 400)
        if len(str(new_pwd)) < 8:
            return make_response({'erro': True, 'message': 'A nova senha precisa ter pelo menos 8 caracteres', 'dados': None}, 400)
        user = find_by_email(email)
        if not user:
            return make_response({'erro': True, 'message': 'Usuário não encontrado', 'dados': None}, 404)
        if not code_is_valid(user, code):
            return make_response({'erro': True, 'message': 'Código inválido ou expirado', 'dados': None}, 400)
        # alterar senha
        hashed = hash_password(new_pwd)
        setattr(user, PASSWORD_FIELD, hashed)
        # invalida código usado
        if hasattr(user, CODE_FIELD):
            setattr(user, CODE_FIELD, str(uuid.uuid4()))
        from %%module_service%% import db, _now
        if hasattr(user, 'dt_update'):
            setattr(user, 'dt_update', _now())
        db.session.commit()
        return make_response({'erro': False, 'message': 'Senha alterada com sucesso', 'dados': None}, 200)

class %%ClassName%%ChangePassword(Resource):
    """
    Troca de senha com usuário logado.
    body: { "no_email": "...", "no_password": "senhaAtual", "new_password": "novaSenha" }
    """
    @jwt_required()
    def post(self):
        data = request.json or {}
        email = data.get('no_email')
        current = data.get('no_password')
        new_pwd = data.get('new_password')
        if not email or not current or not new_pwd:
            return make_response({'erro': True, 'message': 'no_email, no_password e new_password são obrigatórios', 'dados': None}, 400)
        if len(str(new_pwd)) < 8:
            return make_response({'erro': True, 'message': 'A nova senha precisa ter pelo menos 8 caracteres', 'dados': None}, 400)
        user = find_by_email(email)
        if not user:
            return make_response({'erro': True, 'message': 'Usuário não encontrado', 'dados': None}, 404)
        if soft_blocked_or_inactive(user):
            return make_response({'erro': True, 'message': 'Usuário inativo/bloqueado', 'dados': None}, 400)
        if not verify_password(current, getattr(user, PASSWORD_FIELD, '') or ''):
            return make_response({'erro': True, 'message': 'A senha atual não confere', 'dados': None}, 400)
        hashed = hash_password(new_pwd)
        setattr(user, PASSWORD_FIELD, hashed)
        from %%module_service%% import db, _now
        if hasattr(user, 'dt_update'):
            setattr(user, 'dt_update', _now())
        db.session.commit()
        return make_response({'erro': False, 'message': 'Senha alterada com sucesso', 'dados': None}, 200)

# Registro das rotas de auth
api.add_resource(%%ClassName%%Login, '/%%singular%%/login')
api.add_resource(%%ClassName%%Refresh, '/%%singular%%/refresh')
api.add_resource(%%ClassName%%SendCode, '/%%singular%%/password/code')
api.add_resource(%%ClassName%%ValidateCode, '/%%singular%%/password/validate')
api.add_resource(%%ClassName%%ResetPassword, '/%%singular%%/password')
api.add_resource(%%ClassName%%ChangePassword, '/%%singular%%/password/change')
'''

# ---------- geração da entidade encapsulada ----------

def _init_param_for_field(c):
    nome = c["nome"]
    default = default_py_value(c)
    obrig = bool(c.get("obrigatorio"))
    if obrig and default is None:
        return nome
    if default in ("datetime.utcnow", "date.today"):
        return f"{nome}=None"
    if default is not None:
        return f"{nome}={default}"
    return f"{nome}=None"

def _init_body_for_field(c):
    nome = c["nome"]
    default = default_py_value(c)
    if default == "datetime.utcnow":
        return f"self.__{nome} = datetime.utcnow() if {nome} is None else {nome}"
    if default == "date.today":
        return f"self.__{nome} = date.today() if {nome} is None else {nome}"
    return f"self.__{nome} = {nome}"

def _property_block_for_field(c):
    nome = c["nome"]
    priv = f"__{nome}"
    t = c["tipo"].lower()
    obrig = bool(c.get("obrigatorio"))
    tam = c.get("tam", None) if t == "str" else None

    getter = f"""@property
def {nome}(self):
    return self.{priv}
"""

    validations = []
    if obrig:
        validations.append(f"if value is None:\n            raise ValueError(\"{nome} é obrigatório\")")
    if t == "str" and tam:
        validations.append(f"if value is not None and len(value) > {int(tam)}:\n            raise ValueError(\"{nome} excede o tamanho máximo de {int(tam)}\")")

    type_checks = {
        "int": "int",
        "float": "float",
        "bool": "bool",
    }
    if t in type_checks:
        validations.append(f"if value is not None and not isinstance(value, {type_checks[t]}):\n            raise TypeError(\"{nome} deve ser do tipo {type_checks[t]}\")")

    setter_body = "\n        ".join(validations) + ("\n        " if validations else "")
    setter = f"""@{nome}.setter
def {nome}(self, value):
        {setter_body}self.{priv} = value
"""

    return getter + "\n" + setter

def build_entity_encapsulated_parts(campos):
    init_params = ", ".join(_init_param_for_field(c) for c in campos)
    init_body_lines = [_init_body_for_field(c) for c in campos]
    init_body = indent("\n".join(init_body_lines), 8)
    properties = "\n".join(_property_block_for_field(c) for c in campos)
    properties = indent(properties.rstrip() + "\n", 4)
    return init_params, init_body, properties
    
def build_schema_params(campos):
    init_params = ", ".join(c["nome"] for c in campos)
    return init_params

# ---------- geração de conteúdo restante ----------

def build_model_columns(campos, id_field_guess="id"):
    lines = []
    id_field = None
    for c in campos:
        if c.get("primary_key"):
            id_field = c["nome"]
            break
    if not id_field:
        id_field = id_field_guess if any(c["nome"] == id_field_guess for c in campos) else campos[0]["nome"]

    for c in campos:
        col_def = build_sqla_column(c)
        lines.append(f"    {c['nome']} = {col_def}")
    return "\n".join(lines), id_field

def build_schema_fields(campos):
    lines = []
    for c in campos:
        mm = map_marshmallow_field(c)
        allow_none = "True" if not c.get("obrigatorio") else "False"
        validate_part = ""
        if c["tipo"].lower() == "str" and "tam" in c:
            try:
                tam = int(c["tam"])
                validate_part = f", validate=validate.Length(max={tam})"
            except Exception:
                pass
        # esconder password em dumps (se o nome for típico)
        extra = ""
        if c["nome"].lower() in ("password","no_password","senha","pwd"):
            extra = ", load_only=True"
        lines.append(f"    {c['nome']} = ma.auto_field()")
        #lines.append(f"    {c['nome']} = {mm}(allow_none={allow_none}{validate_part}{extra})")
    return "\n".join(lines)

def build_service_file_augments(file_field_names, plural, bp_name):
    if not file_field_names:
        return "pass"
    pieces = []
    for f in file_field_names:
        pieces.append(
            f"""if obj_dict.get("{f}"):
        obj_dict["{f}_url"] = f"/{plural}/" + str(obj_dict.get("id") or obj_dict.get("co_user") or '') + "/{f}" """
        )
    return "\n    ".join(pieces)

def build_service_file_assign_create(file_field_names):
    if not file_field_names:
        return ""
    lines = ['data = dict(data)  # cópia editável']
    for f in file_field_names:
        lines.append(f'if files.get("{f}"):')
        lines.append(indent(f'data["{f}"] = _save_file(files.get("{f}"))', 4))
    return "\n    ".join(lines)

def build_service_file_assign_update(file_field_names):
    if not file_field_names:
        return ""
    lines = []
    for f in file_field_names:
        lines.append(f'if files.get("{f}"):')
        lines.append(indent(f'new_name = _save_file(files.get("{f}"))', 4))
        lines.append(indent(f'if new_name: setattr(obj, "{f}", new_name)', 4))
    return "\n    ".join(lines)

# --------- VIEW: recursos de download (Flask-RESTful) ---------

def build_restful_download_resources(class_name, plural, file_field_names):
    if not file_field_names:
        return "", ""
    resource_blocks = []
    add_resource_lines = []
    for f in file_field_names:
        res_name = f"{class_name}{f.capitalize()}Download"
        block = f'''class {res_name}(Resource):
    @jwt_required()
    def get(self, id):
        obj = {class_name}.query.get(id)
        if not obj or not getattr(obj, "{f}", None):
            return make_response(jsonify('arquivo não encontrado'), 404)
        return send_from_directory(UPLOAD_DIR, getattr(obj, "{f}"), as_attachment=True)
'''
        resource_blocks.append(block)
        add_resource_lines.append(f"api.add_resource({res_name}, '/{plural}/<int:id>/{f}')")
    return "\n".join(resource_blocks) + "\n", "\n".join(add_resource_lines)

def render(tmpl: str, mapping: dict) -> str:
    out = tmpl
    for k, v in mapping.items():
        out = out.replace(f"%%{k}%%", v)
    return out

# ---------- main ----------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Caminho do JSON da entidade")
    parser.add_argument("--outdir", default=".", help="Diretório de saída (onde gerar os arquivos)")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    class_name = data["nome"]
    campos = data["campos"]
    senha_flag = bool(data.get("senha", False))

    outdir = Path(args.outdir).resolve()
    ensure_dirs(outdir)

    module_prefix = to_snake(class_name)  # ex.: user
    plural = to_plural(module_prefix)     # ex.: users
    singular = module_prefix

    # usa nome_tabela se existir; senão, plural
    table_name = data.get("nome_tabela", plural)

    # ENTITY (encapsulada)
    init_params, init_body, properties = build_entity_encapsulated_parts(campos)
    entity_code = render(ENTITY_TMPL, {
        "ClassName": class_name,
        "init_params": init_params,
        "init_body": init_body,
        "properties": properties,
    })

    # MODEL
    model_columns, id_field = build_model_columns(campos)
    model_code = render(MODEL_TMPL, {
        "ClassName": class_name,
        "table_name": table_name,
        "columns": model_columns,
        "id_field": id_field
    })

    # SCHEMA
    schema_fields = build_schema_fields(campos)
    fields_sch = build_schema_params(campos)
    schema_code = render(SCHEMA_TMPL, {
        "ClassName": class_name,
        "module_model": f"{module_prefix}_model",
        "init_params": fields_sch,
        "fields": schema_fields,
    })

    # SERVICE
    ff = file_fields(campos)
    file_url_aug = build_service_file_augments(ff, plural, module_prefix)
    file_assign_create = build_service_file_assign_create(ff)
    file_assign_update = build_service_file_assign_update(ff)
    order_field = "created_at" if any(c["nome"] == "created_at" for c in campos) else id_field

    service_code = render(SERVICE_TMPL, {
        "ClassName": class_name,
        "module_model": f"{module_prefix}_model",
        "module_schema": f"{module_prefix}_schema",
        "file_url_augment": file_url_aug or "pass",
        "file_assign_create": file_assign_create or "",
        "file_assign_update": file_assign_update or "",
        "order_field": order_field,
        "id_field": id_field,
    })

    # VIEW (CRUD)
    download_resources, add_resource_downloads = build_restful_download_resources(class_name, plural, ff)
    view_code = render(VIEW_RESTFUL_TMPL, {
        "ClassName": class_name,
        "module_service": f"{module_prefix}_service",
        "module_schema": f"{module_prefix}_schema",
        "module_model": f"{module_prefix}_model",
        "plural": plural,
        "file_download_resources": download_resources or "",
        "add_resource_downloads": add_resource_downloads or ""
    })

    files = {
        f"{module_prefix}_entity.py": entity_code,
        f"{module_prefix}_model.py": model_code,
        f"{module_prefix}_schema.py": schema_code,
        f"{module_prefix}_service.py": service_code,
        f"{module_prefix}_view.py": view_code,
    }

    # VIEW AUTH (se senha:true)
    if senha_flag:
        auth_code = render(AUTH_VIEW_TMPL, {
            "ClassName": class_name,
            "module_service": f"{module_prefix}_service",
            "module_schema": f"{module_prefix}_schema",
            "module_model": f"{module_prefix}_model",
            "singular": singular,
        })
        files[f"{module_prefix}_auth_view.py"] = auth_code

    # Escreve arquivos
    for fname, code in files.items():
        (outdir / fname).write_text(code.rstrip() + "\n", encoding="utf-8")

    print("Arquivos gerados com sucesso em:", outdir)
    for fname in files:
        print(" -", fname)
    print("\nIntegração:")
    print("  • from {0}_view import *  # rotas CRUD (Flask-RESTful)".format(module_prefix))
    if senha_flag:
        print("  • from {0}_auth_view import *  # rotas de auth (login/reset/refresh/ativação)".format(module_prefix))
    print("  • Ajuste send_email_html no service para seu provedor de e-mail.")

if __name__ == "__main__":
    main()
