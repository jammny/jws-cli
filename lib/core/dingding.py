from dingtalkchatbot.chatbot import DingtalkChatbot

from lib.core.log import logger


def dingtalk_robot(webhook: str, secret: str, text: str):
    try:
        bot = DingtalkChatbot(webhook, secret)
        bot.send_markdown(
            title=f'来自JWS的推送',
            text=text,
            is_at_all=True
        )
        logger.info("Dingding sent successfully！")
    except Exception as e:
        logger.error(f"[red]DingDing sending failed！ {e}[/red]")
