import requests
from PIL import Image
from io import BytesIO
from bs4 import BeautifulSoup
from captcha_ocr import get_ocr_res
import os
from dotenv import load_dotenv
import json
from dingtalk import dingtalk
from feishu import feishu
import logging
import re

load_dotenv()

# 钉钉机器人推送
DD_BOT_TOKEN = os.getenv("DD_BOT_TOKEN")
DD_BOT_SECRET = os.getenv("DD_BOT_SECRET")

# 飞书机器人推送
FEISHU_BOT_URL = os.getenv("FEISHU_BOT_URL")
FEISHU_BOT_SECRET = os.getenv("FEISHU_BOT_SECRET")

# 学期配置
SEMESTER = os.getenv("SEMESTER", "2025-2026-1")  # 默认值为当前学期

# 设置日志配置
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# 设置基本的URL和数据
# 山东建筑大学
RandCodeUrl = "https://xjwgl.sdjzu.edu.cn/jsxsd/verifycode.servlet"  # 验证码请求URL
loginUrl = "https://xjwgl.sdjzu.edu.cn/Logon.do?method=logon"  # 登录请求URL
dataStrUrl = (
    "https://xjwgl.sdjzu.edu.cn/Logon.do?method=logon&flag=sess"  # 初始数据请求URL
)


def get_initial_session():
    """
    创建会话并获取初始数据
    返回: (session对象, cookies字典, 初始数据字符串)
    """
    session = requests.session()
    response = session.get(dataStrUrl, timeout=1000)
    cookies = session.cookies.get_dict()
    return session, cookies, response.text


def handle_captcha(session, cookies):
    """
    获取并识别验证码
    返回: 识别出的验证码字符串
    """
    response = session.get(RandCodeUrl, cookies=cookies)

    # 添加调试信息
    if response.status_code != 200:
        logging.error(f"请求验证码失败，状态码: {response.status_code}")
        return None

    try:
        image = Image.open(BytesIO(response.content))
    except Exception as e:
        logging.error(f"无法识别图像文件: {e}")
        return None

    return get_ocr_res(image)


def generate_encoded_string(data_str, user_account, user_password):
    """
    生成登录所需的encoded字符串
    参数:
        data_str: 初始数据字符串
        user_account: 用户账号
        user_password: 用户密码
    返回: encoded字符串
    """
    res = data_str.split("#")
    code, sxh = res[0], res[1]
    data = f"{user_account}%%%{user_password}"
    encoded = ""
    b = 0

    for a in range(len(code)):
        if a < 20:
            encoded += data[a]
            for _ in range(int(sxh[a])):
                encoded += code[b]
                b += 1
        else:
            encoded += data[a:]
            break
    return encoded


def login(session, cookies, user_account, user_password, random_code, encoded):
    """
    执行登录操作
    返回: 登录响应结果
    """
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
        "Origin": "https://xjwgl.sdjzu.edu.cn",
        "Referer": "https://xjwgl.sdjzu.edu.cn/",
        "Upgrade-Insecure-Requests": "1",
    }

    data = {
        "userAccount": user_account,
        "userPassword": user_password,
        "encoded": encoded,
    }

    return session.post(
        loginUrl, headers=headers, data=data, cookies=cookies, timeout=1000
    )


def get_user_credentials():
    """
    获取用户账号和密码
    返回: (user_account, user_password)
    """
    user_account = os.getenv("USER_ACCOUNT")
    user_password = os.getenv("USER_PASSWORD")
    if user_account and user_password:
        logging.info(f"用户名: {user_account[:2]}{'*' * (len(user_account)-2)}")
        logging.info(f"密码: {'*' * len(user_password)}")
    else:
        logging.error("请在.env文件中设置USER_ACCOUNT和USER_PASSWORD环境变量")
        return None, None
    return user_account, user_password


def simulate_login(user_account, user_password):
    """
    模拟登录过程
    返回: (session对象, cookies字典)
    抛出:
        Exception: 当验证码错误时
    """
    session, cookies, data_str = get_initial_session()

    for attempt in range(3):  # 尝试三次
        random_code = handle_captcha(session, cookies)
        logging.info(f"验证码: {random_code}")
        encoded = generate_encoded_string(data_str, user_account, user_password)
        # 禁用自动重定向以处理302响应
        response = session.post(
            loginUrl, 
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
                "Origin": "https://xjwgl.sdjzu.edu.cn",
                "Referer": "https://xjwgl.sdjzu.edu.cn/",
                "Upgrade-Insecure-Requests": "1",
            }, 
            data={
                "userAccount": user_account,
                "userPassword": user_password,
                "encoded": encoded,
            }, 
            cookies=cookies, 
            timeout=1000,
            allow_redirects=False
        )

        # 检查响应状态码和内容
        if response.status_code == 302:
            logging.info("登录成功！收到重定向响应")
            location = response.headers.get('Location')
            logging.info(f"重定向地址: {location}")
            # 处理重定向，完成登录流程
            if location:
                if not location.startswith('http'):
                    location = f"https://xjwgl.sdjzu.edu.cn{location}"
                redirect_response = session.get(location, cookies=cookies, allow_redirects=True)
                cookies.update(redirect_response.cookies)
                logging.info("登录流程完成")
            return session, cookies
            
        elif response.status_code == 200:
            if "验证码错误!!" in response.text:
                logging.warning(f"验证码识别错误，重试第 {attempt + 1} 次")
                continue  # 继续尝试
            if "密码错误" in response.text or "用户名或密码错误" in response.text:
                raise Exception("用户名或密码错误")
            if "登录成功" in response.text or "欢迎" in response.text:
                logging.info("登录成功，cookies已返回")
                return session, cookies
            else:
                logging.warning(f"登录响应异常，响应内容: {response.text[:100]}...")
                raise Exception("登录响应异常")
        else:
            logging.error(f"登录请求失败，状态码: {response.status_code}")
            raise Exception(f"登录请求失败，状态码: {response.status_code}")

    raise Exception("验证码识别错误，请重试")


# 访问成绩页面
def get_score_page(session, cookies):
    url = "https://xjwgl.sdjzu.edu.cn/jsxsd/kscj/cjcx_list"
    response = session.get(url, cookies=cookies, timeout=1000)
    return response.text


# 解析成绩页面
def analyze_score_page(pagehtml):
    soup = BeautifulSoup(pagehtml, "lxml")
    results = []

    # 找到成绩表格 - 山东建筑大学的表格可能没有id
    tables = soup.find_all("table")
    if not tables:
        logging.error("页面中没有找到表格")
        return results

    for table in tables:
        rows = table.find_all("tr")
        if not rows:
            continue

        # 遍历表格的每一行（跳过表头行）
        for row in rows[1:]:
            columns = row.find_all("td")
            if not columns:
                continue

            subject_name = None
            score = None
            name_col = -1
            chinese_subject_name = None
            chinese_col = -1

            # 寻找包含中文的课程名称列
            for i in range(2, min(10, len(columns))):  # 检查前10列中的前2-9列
                cell_content = columns[i].get_text(strip=True)
                if cell_content and re.search(r"[\u4e00-\u9fa5]", cell_content):  # 检查是否包含中文
                    chinese_subject_name = cell_content
                    chinese_col = i
                    break

            # 如果找到中文课程名称
            if chinese_subject_name and chinese_col != -1:
                name_col = chinese_col
                subject_name = chinese_subject_name
            else:
                # 如果没有找到中文，使用默认的第3列（索引为2）
                if len(columns) > 2:
                    name_col = 2
                    subject_name = columns[2].get_text(strip=True)

            # 从课程名称列之后的列中查找成绩
            if subject_name and name_col != -1:
                # 检查课程名称列之后的8列以内（可能的成绩列）
                for i in range(name_col + 1, min(name_col + 8, len(columns))):
                    cell_content = columns[i].get_text(strip=True)
                    cleaned_content = cell_content.replace(" ", "").replace("--", "").strip()
                    if cleaned_content and any(c.isdigit() for c in cleaned_content):
                        number_match = re.search(r"(\d+(?:\.\d+)?)", cleaned_content)
                        if number_match:
                            score = number_match.group(1)
                            break

            if subject_name and score:
                results.append((subject_name, score))

    logging.info(f"成功解析到 {len(results)} 门课程的成绩")
    return results


# 分离新增成绩的科目和成绩
def get_new_scores(current_scores, last_scores):
    """
    获取新增的成绩
    参数:
        current_scores: 当前获取的成绩列表
        last_scores: 上一次获取的成绩列表
    返回: 新增成绩的列表
    """

    # 在current_scores中找出last_scores中不存在的元素
    new_scores = [score for score in current_scores if score not in last_scores]

    return new_scores


def print_welcome():
    logging.info("\n" * 10)
    logging.info(f"\n{'*' * 10} 山东建筑大学成绩监控脚本 {'*' * 10}\n")
    logging.info("By W1ndys")
    logging.info("https://github.com/W1ndys/QFNUScoreReminder")
    logging.info("https://www.w1ndys.top")


def save_scores_to_file(scores, filename="scores.json"):
    """
    将成绩保存到本地文件
    参数:
        scores: 成绩列表
        filename: 保存的文件名
    返回:
        bool: 保存是否成功
    """
    try:
        # 确保目录存在
        os.makedirs(
            os.path.dirname(filename) if os.path.dirname(filename) else ".",
            exist_ok=True,
        )
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(scores, f, ensure_ascii=False, indent=4)
        logging.info(f"成绩保存到文件 {filename} 成功")
        return True
    except Exception as e:
        logging.error(f"成绩保存到文件 {filename} 失败: {e}")
        return False


def safe_file_write(filename, content, mode="w", encoding="utf-8"):
    """
    安全地写入文件，如果目录不存在则创建
    参数:
        filename: 文件名
        content: 要写入的内容
        mode: 写入模式
        encoding: 文件编码
    """
    try:
        # 确保目录存在
        os.makedirs(
            os.path.dirname(filename) if os.path.dirname(filename) else ".",
            exist_ok=True,
        )

        with open(filename, mode, encoding=encoding) as f:
            f.write(content)
        return True
    except Exception as e:
        logging.error(f"写入文件 {filename} 失败: {e}")
        return False


def load_scores_from_file(filename="scores.json"):
    """
    从本地文件加载成绩
    参数:
        filename: 文件名
    返回: 成绩列表
    """
    try:
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                data = f.read()
                if data.strip():  # 检查文件是否有数据
                    return json.loads(data)
                else:
                    logging.info(f"文件 {filename} 为空，初始化为空列表")
                    return []
        else:
            logging.info(f"文件 {filename} 不存在，创建新文件")
            # 确保目录存在
            os.makedirs(
                os.path.dirname(filename) if os.path.dirname(filename) else ".",
                exist_ok=True,
            )
            with open(filename, "w", encoding="utf-8") as f:
                f.write("[]")
            return []
    except Exception as e:
        logging.error(f"读取文件 {filename} 失败: {e}")
        return []


# 获取全部学期的绩点和学分
def get_all_semester_scores(session, cookies):
    """
    获取全部学期的绩点和学分
    参数:
        session: requests会话对象
        cookies: 会话cookies
    返回: 总学分和平均绩点
    """
    url = "https://xjwgl.sdjzu.edu.cn/jsxsd/kscj/cjcx_list"
    response = session.get(url, cookies=cookies, timeout=1000)

    # 使用正则表达式提取总学分和平均绩点
    total_credits_match = re.search(r"所修总学分:(\d+)", response.text)
    average_gpa_match = re.search(r"平均学分绩点:(\d+\.\d+)", response.text)

    if total_credits_match and average_gpa_match:
        total_credits = total_credits_match.group(1)
        average_gpa = average_gpa_match.group(1)
        return total_credits, average_gpa
    else:
        return None, None


# 解析HTML页面，返回学分和绩点的元组列表
def parse_credits_and_gpa(session, cookies):
    """
    解析HTML页面，返回学分和绩点的元组列表
    参数:
        html_content: HTML页面内容
    返回: [(学分, 绩点), ...] 的列表
    """
    url = f"https://xjwgl.sdjzu.edu.cn/jsxsd/kscj/cjcx_list?kksj={SEMESTER}&kcxz=&kcmc=&xsfs=all"
    response = session.get(url, cookies=cookies, timeout=1000)
    soup = BeautifulSoup(response.text, "lxml")
    results = []

    # 找到成绩表格
    table = soup.find("table", {"id": "dataList"})
    if table:
        # 遍历表格的每一行
        rows = table.find_all("tr")[1:]  # 跳过表头 # type: ignore
        for row in rows:
            columns = row.find_all("td")
            if len(columns) > 9:  # 确保有足够的列
                try:
                    credits = float(columns[7].get_text(strip=True))
                    gpa = float(columns[9].get_text(strip=True))
                    results.append((credits, gpa))
                except ValueError:
                    # 如果转换失败，跳过该行
                    continue

    return results


# 计算平均学分绩点
def calculate_average_gpa(credits_and_points):
    """
    计算平均学分绩点
    参数:
        credits_and_points: [(学分, 绩点), ...] 的列表
    返回: 平均学分绩点
    """
    total_points = 0
    total_credits = 0

    for credit, grade_point in credits_and_points:
        total_points += grade_point * credit
        total_credits += credit

    if total_credits == 0:
        return 0

    return total_points / total_credits


def validate_credentials(user_account, user_password):
    """
    验证用户凭据是否存在
    """
    logging.info("获取环境变量")
    if not user_account or not user_password:
        logging.error(
            "请在.env文件中设置USER_ACCOUNT、USER_PASSWORD、DD_BOT_TOKEN、DD_BOT_SECRET、FEISHU_BOT_URL、FEISHU_BOT_SECRET、SEMESTER环境变量"
        )
        with open(".env", "w", encoding="utf-8") as f:
            f.write(
                "USER_ACCOUNT=\nUSER_PASSWORD=\nDD_BOT_TOKEN=\nDD_BOT_SECRET=\nFEISHU_BOT_URL=\nFEISHU_BOT_SECRET=\nSEMESTER=2024-2025-2"
            )
        return False
    logging.info("获取环境变量成功")
    return True


def notify_connection_issue(user_account):
    """
    通知用户连接问题
    """
    logging.error("无法建立会话，请检查网络连接或教务系统的可用性。")
    if DD_BOT_TOKEN and DD_BOT_SECRET:
        dingtalk(
            DD_BOT_TOKEN,
            DD_BOT_SECRET,
            "成绩监控通知",
            f"学号: {user_account}\n无法建立会话，请检查网络连接或教务系统的可用性。",
        )
    if FEISHU_BOT_SECRET:
        feishu(
            DD_BOT_TOKEN,
            DD_BOT_SECRET,
            "成绩监控通知",
            f"学号: {user_account}\n无法建立会话，请检查网络连接或教务系统的可用性。",
        )


def process_scores(session, cookies, user_account):
    """
    处理成绩信息
    """
    last_score_list = load_scores_from_file()
    score_page = get_score_page(session, cookies)
    score_list = analyze_score_page(score_page)
    score_list_converted = [list(score) for score in score_list]

    if not last_score_list:
        initialize_scores(score_list_converted, user_account)
    elif score_list_converted != last_score_list:
        logging.info("更新成绩")
        update_scores(score_list_converted, last_score_list, user_account)
    else:
        logging.info("没有新成绩")


def initialize_scores(score_list_converted, user_account):
    """
    初始化保存当前成绩
    """
    logging.info("初始化保存当前成绩")
    save_scores_to_file(score_list_converted)
    notify_new_scores("初始化保存当前成绩成功", user_account, "初始化保存当前成绩成功")


def update_scores(score_list_converted, last_score_list, user_account):
    """
    更新成绩并通知用户
    """
    new_scores = get_new_scores(score_list_converted, last_score_list)

    if new_scores:
        logging.info(f"发现新成绩！{new_scores}")
        message = "\n".join(
            [f"科目: {score[0]}\n成绩: {score[1]}" for score in new_scores]
        )
        # 生成邮件标题
        email_subject = "\n".join(
            [f"科目: {score[0]}\n成绩: {score[1]}" for score in new_scores]
        )
        notify_new_scores(message, user_account, email_subject)
        save_scores_to_file(score_list_converted)


def notify_new_scores(message, user_account, email_subject):
    """
    通过钉钉和邮箱通知新成绩
    """
    if DD_BOT_TOKEN and DD_BOT_SECRET:
        dingtalk(
            DD_BOT_TOKEN,
            DD_BOT_SECRET,
            "成绩监控通知",
            f"学号: {user_account}\n{message}",
        )
    if FEISHU_BOT_SECRET:
        feishu(
            DD_BOT_TOKEN,
            DD_BOT_SECRET,
            email_subject,
            f"学号: {user_account}\n{message}",
        )


def handle_exception(e, user_account):
    """
    处理异常并通知用户
    """
    logging.error(f"发生错误: {e}")
    if DD_BOT_TOKEN and DD_BOT_SECRET:
        dingtalk(
            DD_BOT_TOKEN,
            DD_BOT_SECRET,
            "成绩监控通知",
            f"学号: {user_account}\n发生错误: {e}",
        )
    if FEISHU_BOT_SECRET:
        feishu(
            DD_BOT_TOKEN,
            DD_BOT_SECRET,
            "成绩监控通知",
            f"学号: {user_account}\n发生错误: {e}",
        )


def main():
    """
    主函数，协调整个程序的执行流程
    """
    print_welcome()
    logging.info("开始执行")
    try:
        user_account, user_password = get_user_credentials()
        if not validate_credentials(user_account, user_password):
            return

        session, cookies = simulate_login(user_account, user_password)
        if not session or not cookies:
            notify_connection_issue(user_account)
            return
        logging.info("开始处理成绩")
        process_scores(session, cookies, user_account)

        # 获取全部学期的总学分和平均绩点
        total_credits, average_gpa = get_all_semester_scores(session, cookies)
        logging.info(f"总学分: {total_credits}, 平均绩点: {average_gpa}")

        # 使用安全的文件写入方法
        if not safe_file_write(
            "output.txt", f"总学分: {total_credits}, 平均绩点: {average_gpa}\n"
        ):
            logging.error("保存总学分和平均绩点数据失败")
        else:
            logging.info("总学分和平均绩点数据保存成功")

        # 计算本学期绩点
        credits_and_points = parse_credits_and_gpa(session, cookies)
        semester_average_gpa = calculate_average_gpa(credits_and_points)
        logging.info(f"{SEMESTER}平均绩点: {semester_average_gpa}")

        # 追加写入本学期绩点
        if not safe_file_write(
            "output.txt", f"{SEMESTER}平均绩点: {semester_average_gpa}\n", mode="a"
        ):
            logging.error(f"保存{SEMESTER}平均绩点数据失败")

    except Exception as e:
        handle_exception(e, user_account)


if __name__ == "__main__":
    main()
