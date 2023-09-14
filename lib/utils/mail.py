#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 邮件发送模块。
"""
from dataclasses import dataclass
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formataddr

from lib.core.log import logger
from lib.core.settings import SEND_EMAIL, SEND_PASS, REC_EMAIL, SMTP_SERVER, SMTP_PORT


@dataclass()
class SendEmail:
    mail_header: str    # 邮件的主题

    my_sender = SEND_EMAIL  # 发件人邮箱账号
    my_pass = SEND_PASS     # 发件人邮箱密码
    my_user = REC_EMAIL     # 收件人邮箱账号
    smtp_server = SMTP_SERVER
    smtp_port = SMTP_PORT

    def send_file(self, mail_msg: str, file_name: str, report_name: str):
        try:
            if ',' in self.my_user:
                receivers = self.my_user.split(',')
            else:
                receivers = [self.my_user]  # 接收邮件，可设置为你的QQ邮箱或者其他邮箱
            msg = MIMEMultipart()  # 设置电子邮件消息
            msg['Subject'] = self.mail_header  # 邮件的主题
            msg['From'] = formataddr(("JWS", self.my_sender))
            msg['To'] = formataddr(("", self.my_user))
            msg.attach(MIMEText(f"{mail_msg}", 'plain'))

            # 压缩文件
            with open(file_name, 'rb') as f:
                attach = MIMEApplication(f.read(), _subtype='zip')
                attach.add_header('Content-Disposition', 'attachment', filename=report_name)
                msg.attach(attach)

            server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)  # 发件人邮箱中的SMTP服务器
            server.login(self.my_sender, self.my_pass)  # 括号中对应的是发件人邮箱账号、邮箱密码
            server.sendmail(self.my_sender, receivers, msg.as_string())  # 括号中对应的是发件人邮箱账号、收件人邮箱账号、发送邮件
            server.quit()  # 关闭连接
            logger.info("[g]Email sent successfully![/g]")
        except Exception as e:
            logger.error(f"[red]Email sending failed! {e} [/red]")

    def send_msg(self, mail_msg: str):
        try:
            if ',' in self.my_user:
                receivers = self.my_user.split(',')
            else:
                receivers = [self.my_user]  # 接收邮件，可设置为你的QQ邮箱或者其他邮箱
            message = MIMEText(mail_msg, 'plain', 'utf-8')
            message['From'] = Header("JWS", 'utf-8')
            message['To'] = Header("测试", 'utf-8')
            message['Subject'] = Header(self.mail_header, 'utf-8')
            smtpObj = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            smtpObj.login(self.my_sender, self.my_pass)
            smtpObj.sendmail(self.my_sender, receivers, message.as_string())
            logger.info("Email sent successfully！")
        except Exception as e:
            logger.error(f"[red]Email sending failed！ {e}[/red]")
