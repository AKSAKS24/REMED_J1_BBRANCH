from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import re

app = FastAPI()


class Payload(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    code: str


class ResponseModel(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    original_code: str
    remediated_code: str


def process_abap_code(payload: Payload):
    code = payload.code
    original_code = code
    today_str = datetime.now().strftime("%Y-%m-%d")
    tag = f"\"Added By Pwc {today_str}"

    remediated_code = code

    # --- Case 1: Replace field references (j_1bbranch-field or j_1bbranch~field)
    pattern_field = re.compile(r'\bj_1bbranch([-~])([a-zA-Z_]\w*)', re.IGNORECASE)
    remediated_code = pattern_field.sub(
        lambda m: f"p_businessplace{m.group(1)}{m.group(2)} {tag}", remediated_code
    )

    # --- Case 2: Replace standalone table/type references J_1BBRANCH
    # Avoid replacing if followed by - or ~ (already handled above)
    pattern_table = re.compile(r'\bj_1bbranch\b(?![-~])', re.IGNORECASE)
    remediated_code = pattern_table.sub(
        lambda m: f"P_BusinessPlace {tag}", remediated_code
    )

    return ResponseModel(
        pgm_name=payload.pgm_name,
        inc_name=payload.inc_name,
        type=payload.type,
        name=payload.name,
        class_implementation=payload.class_implementation,
        original_code=original_code,
        remediated_code=remediated_code,
    )


@app.post('/remediate_abap', response_model=ResponseModel)
async def remediate_abap(payload: Payload):
    return process_abap_code(payload)
