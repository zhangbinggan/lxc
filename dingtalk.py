# 用于发送钉钉通知
import requests
import json
import time
import hmac
import hashlib
import urllib
import base64
import urllib.parse
import logging


# 推送到钉钉
def dingtalk(DD_BOT_TOKEN, DD_BOT_SECRET, text, desp):

    url = f"https://oapi.dingtalk.com/robot/send?access_token={DD_BOT_TOKEN}"
    headers = {"Content-Type": "application/json"}
    payload = {"msgtype": "text", "text": {"content": f"{text}\n{desp}"}}

    if DD_BOT_TOKEN and DD_BOT_SECRET:
        timestamp = str(round(time.time() * 1000))
        secret_enc = DD_BOT_SECRET.encode("utf-8")
        string_to_sign = f"{timestamp}\n{DD_BOT_SECRET}"
        string_to_sign_enc = string_to_sign.encode("utf-8")
        hmac_code = hmac.new(
            secret_enc, string_to_sign_enc, digestmod=hashlib.sha256
        ).digest()
        sign = urllib.parse.quote_plus(
            base64.b64encode(hmac_code).decode("utf-8").strip()
        )
        url = f"{url}&timestamp={timestamp}&sign={sign}"

        # 添加日志检查URL和签名（脱敏处理）
        safe_token = (
            DD_BOT_TOKEN[:6] + "***" + DD_BOT_TOKEN[-4:]
            if len(DD_BOT_TOKEN) > 10
            else "***"
        )
        safe_secret = (
            DD_BOT_SECRET[:6] + "***" + DD_BOT_SECRET[-4:]
            if len(DD_BOT_SECRET) > 10
            else "***"
        )
        safe_url = f"https://oapi.dingtalk.com/robot/send?access_token={safe_token}&timestamp={timestamp}&sign={sign[:10]}***{sign[-6:]}"

        logging.info(f"钉钉请求URL: {safe_url}")
        logging.info(f"钉钉TOKEN(脱敏): {safe_token}")
        logging.info(f"钉钉SECRET(脱敏): {safe_secret}")
        logging.info(f"钉钉签名字符串(脱敏): {timestamp}\n{safe_secret}")
        logging.info(f"钉钉签名(脱敏): {sign[:10]}***{sign[-6:]}")
    else:
        logging.warning("钉钉TOKEN或SECRET未配置，使用无签名模式")

    logging.info(f"钉钉请求头: {headers}")
    logging.info(f"钉钉请求载荷: {json.dumps(payload, ensure_ascii=False)}")

    response = requests.post(url, headers=headers, data=json.dumps(payload))

    # 改进返回值打印
    logging.info(f"钉钉响应状态码: {response.status_code}")
    logging.info(f"钉钉响应头: {dict(response.headers)}")

    try:
        data = response.json()
        logging.info(f"钉钉响应数据: {json.dumps(data, ensure_ascii=False, indent=2)}")

        if response.status_code == 200 and data.get("errcode") == 0:
            logging.info("钉钉发送通知消息成功🎉")
        else:
            logging.error(
                f"钉钉发送通知消息失败😞\n错误码: {data.get('errcode')}\n错误信息: {data.get('errmsg')}"
            )
    except Exception as e:
        logging.error(f"钉钉发送通知消息失败😞\n异常: {e}")
        logging.error(f"钉钉响应原始内容: {response.text}")
        return {"error": str(e), "response_text": response.text}

    return response.json()


if __name__ == "__main__":
    DD_BOT_SECRET = "x"
    DD_BOT_TOKEN = "x"
    dingtalk(DD_BOT_TOKEN, DD_BOT_SECRET, "test", "test")
