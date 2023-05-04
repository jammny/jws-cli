#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 邮件发送模块。
"""
from dataclasses import dataclass
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formataddr

from lib.utils.log import logger
from lib.core.settings import SEND_EMAIL, SEND_PASS, REC_EMAIL, SMTP_SERVER, SMTP_PORT


@dataclass()
class SendEmail:
    mail_msg: str
    file_name: str

    my_sender = SEND_EMAIL
    my_pass = SEND_PASS
    my_user = REC_EMAIL
    smtp_server = SMTP_SERVER
    smtp_port = SMTP_PORT

    def send(self):
        try:
            msg = MIMEMultipart()  # 设置电子邮件消息
            msg['Subject'] = self.mail_msg  # 邮件的主题
            msg['From'] = formataddr(("JWS", self.my_sender))
            msg['To'] = formataddr(("", self.my_user))
            msg.attach(MIMEText("The information collection scan report has been generated. Click the attachment to "
                                "download it.", 'plain'))

            # 压缩文件
            with open(self.file_name, 'rb') as f:
                attach = MIMEApplication(f.read(), _subtype='zip')
                attach.add_header('Content-Disposition', 'attachment', filename='jws_report.html')
                msg.attach(attach)

            server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)  # 发件人邮箱中的SMTP服务器
            server.login(self.my_sender, self.my_pass)  # 括号中对应的是发件人邮箱账号、邮箱密码
            server.sendmail(self.my_sender, [self.my_user, ], msg.as_string())  # 括号中对应的是发件人邮箱账号、收件人邮箱账号、发送邮件
            server.quit()  # 关闭连接
            logger.debug("Email sent successfully！")
        except Exception as e:
            logger.error(f"Email sending failed！ {e}")
