# Copyright (c) 2025 ByteDance Ltd. and/or its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import os
import logging
from pathlib import Path

class CveContextFilter(logging.Filter):
    def __init__(self, cve_id: str):
        super().__init__()
        self.cve_id = cve_id

    def filter(self, record):
        record.cve = self.cve_id
        return True


def read_json(path):
    with open(path) as fr:
        datas=json.load(fr)
    return datas

def read_jsonl(path):
    datas = []
    with open(path) as f:
        for line in f:
            datas.append(
                json.loads(line)
            )
    return datas

def creat_patch_file(prefix, patch):
    path = f"{prefix}/fix.patch"
    parent_dir = os.path.dirname(path)
    os.makedirs(parent_dir, exist_ok=True)

    with open(path, 'w') as f:
        f.write(patch)
    path = Path(path)
    absolute_path = path.resolve(strict=False)
    return absolute_path, parent_dir

def get_logger(log_path, log_level=logging.INFO):
    log_dir = os.path.dirname(log_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
        
    logger = logging.getLogger('main_logger')
    logger.setLevel(log_level)

    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(cve)s] - %(message)s', defaults={'cve': 'GENERAL'})
        
        handler = logging.FileHandler(log_path, mode='w')
        handler.setFormatter(formatter)
        handler.setLevel(log_level)
        logger.addHandler(handler)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    return logger

def convert_json(json_file, epoch=1):
    origin_datas = read_json(json_file)
    eval_datas = []
    for origin_data in origin_datas:
        for cve, items in origin_data.items():
            for item in items:
                if item['epoch'] == epoch and item['diff_content'] is not None:
                    eval_datas.append({
                        "cve": cve,
                        "fix_patch": item['diff_content'],
                    })
                    break
    return eval_datas


## Addition:

def convert_json_full_function(json_file, input_file, epoch=1):
    """
    Convert full-function LLM output to evaluation format by synthesizing diffs on-the-fly.

    Unlike convert_json (which reads the pre-computed diff_content field), this function
    takes the raw patched functions stored in fix_code and reconstructs a git-apply-
    compatible unified diff using the original snippet and line metadata from input.json.

    Args:
        json_file:  Path to the exp_llm result JSON (e.g. fix_gpt-4_Default_epoch_1_*.json).
        input_file: Path to datasets/input.json (provides snippet, start_line, file_path).
        epoch:      Which epoch to evaluate (1-based, default 1).

    Returns:
        List of {"cve": str, "fix_patch": str} dicts, same shape as convert_json output.
    """
    from diff_synthesizer import synthesize_diff

    origin_datas = read_json(json_file)
    input_datas = read_json(input_file)

    # Build lookup: cve_id -> {vul_id -> vul_func metadata dict}
    cve_vul_info = {}
    for item in input_datas:
        cve = item["cve_id"]
        cve_vul_info[cve] = {vul["id"]: vul for vul in item.get("vul_func", [])}

    eval_datas = []
    for origin_data in origin_datas:
        for cve, items in origin_data.items():
            for item in items:
                if item.get("epoch") != epoch:
                    continue

                fix_code = item.get("fix_code")
                if not fix_code or not isinstance(fix_code, dict):
                    continue  # this entry has no fix_code; keep looking in this CVE's list

                vul_info = cve_vul_info.get(cve, {})
                all_diffs = []

                for vul_id, patched_func in fix_code.items():
                    if not patched_func or vul_id not in vul_info:
                        continue
                    meta = vul_info[vul_id]
                    diff = synthesize_diff(
                        original_snippet=meta["snippet"],
                        patched_function=patched_func,
                        file_path=meta["file_path"],
                        start_line=int(meta["start_line"]),
                    )
                    if diff:
                        all_diffs.append(diff)

                if all_diffs:
                    eval_datas.append({
                        "cve": cve,
                        "fix_patch": "\n".join(all_diffs),
                    })
                break  # first matching epoch found

    return eval_datas