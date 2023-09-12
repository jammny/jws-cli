import json
from typing import Union


def read_json_file(path: str) -> Union[list, dict, None]:
    """读json文件内容

    :param path: 文件路径
    :return:
    """
    try:
        with open(path, mode='r', encoding="utf-8") as f:
            json_data: Union[list, dict] = json.load(f)
        return json_data
    except Exception as e:
        return


def write_txt(path: str, data: list) -> bool:
    """写入目标文件

    :param path: 文件路径
    :param data: 写入数据
    :return:
    """
    try:
        with open(path, mode="w", encoding="utf-8") as f:
            f.write("\n".join(data))
        return True
    except:
        return False
