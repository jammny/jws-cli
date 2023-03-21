#!/usr/bin/python
# -*- coding: UTF-8 -*-

import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr

from lib.core.logger import logger


class SendEmail:
    def __init__(self) -> None:
        self.my_sender = 'jammnyhao@163.com'  # 发件人邮箱账号
        self.my_pass = 'MCLOWLNPIKHMUNWD'  # 发件人邮箱密码
        self.my_user = '798011609@qq.com'  # 收件人邮箱账号

    def send(self, mail_msg) -> bool:
        try:
            msg = MIMEText(mail_msg, 'html', 'utf-8')
            msg['From'] = formataddr(("JWS-CLI", self.my_sender))  # 括号里的对应发件人邮箱昵称、发件人邮箱账号
            msg['To'] = formataddr(("FK", self.my_user))  # 括号里的对应收件人邮箱昵称、收件人邮箱账号
            msg['Subject'] = "JWS-CLI信息推送"  # 邮件的主题

            server = smtplib.SMTP_SSL("smtp.163.com", 465)  # 发件人邮箱中的SMTP服务器
            server.login(self.my_sender, self.my_pass)  # 括号中对应的是发件人邮箱账号、邮箱密码
            server.sendmail(self.my_sender, [self.my_user, ], msg.as_string())  # 括号中对应的是发件人邮箱账号、收件人邮箱账号、发送邮件
            server.quit()  # 关闭连接
        except Exception:
            return False
        return True

    def run(self, ):
        mail_msg = """
        <p>扫描任务完成</p>
"""
        status = self.send(mail_msg)

        if status:
            logger.debug("邮件发送成功！")
        else:
            logger.debug("邮件发送失败！")
