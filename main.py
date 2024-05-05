import logging
import os
import re
import paramiko
from dotenv import load_dotenv
from pathlib import Path
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler

dotenv_path = Path('C:\\Users\\qy\\Desktop\\code\\py\\tg bot\\token.env')
load_dotenv(dotenv_path=dotenv_path)
TOKEN = os.getenv('TOKEN')

logging.basicConfig(
    filename='logfile.txt', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

logger = logging.getLogger(__name__)


def start(update: Update, context):
    user = update.effective_user
    update.message.reply_text(f'Привет, {user.full_name}!')
    logger.info(f'Пользователь {user.full_name} запустил бота.')


def helpCommand(update: Update, context):
    logger.info('Пользователь запросил помощь.')
    update.message.reply_text(
        'Список доступных команд:\n'
        '/findPhoneNumbers - поиск телефонных номеров\n'
        '/findEmailAddresses - поиск email\n'
        '/verifyPassword - проверка сложности пароля\n'
        '/get_auths - последние 10 входов в систему\n'
        '/get_critical - последние 5 критических событий\n'
        '/get_ps - запущенные процессы\n'
        '/get_ss - используемые порты\n'
        '/get_apt_list - установленные пакеты\n'
        '/get_df - состояние файловой системы\n'
        '/get_free - состояние оперативной памяти\n'
        '/get_mpstat - производительность системы\n'
        '/get_w - работающие пользователи\n'
        '/get_release - информация о релизе\n'
        '/get_uname - информация об архитектуре процессора, имени хоста и версии ядра\n'
        '/get_uptime - время работы системы\n'
        '/get_services - запущенные сервисы\n'
    )


def findPhoneNumbersCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска телефонных номеров: ')
    logger.info('Пользователь запросил поиск телефонных номеров.')
    return 'findPhoneNumbers'


def findPhoneNumbers(update: Update, context):
    user_input = update.message.text
    phoneNumRegex = re.compile(r'(?:\+7|8)[\- ]?\(?\d{3}\)?[\- ]?\d{3}[\- ]?\d{2}[\- ]?\d{2}')
    phoneNumberList = phoneNumRegex.findall(user_input)

    if not phoneNumberList:
        update.message.reply_text('Телефонные номера не найдены')
        return

    phoneNumbers = ''
    for i in range(len(phoneNumberList)):
        phoneNumbers += f'{i + 1}. {phoneNumberList[i]}\n'

    update.message.reply_text(phoneNumbers)
    return ConversationHandler.END


def findEmailAddressesCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска email-адресов: ')
    logger.info('Пользователь запросил поиск email-адресов.')
    return 'findEmailAddresses'


def findEmailAddresses(update: Update, context):
    user_input = update.message.text
    emailRegex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

    emailAddressesList = emailRegex.findall(user_input)

    if not emailAddressesList:
        update.message.reply_text('Email-адреса не найдены')
        return ConversationHandler.END

    emailAddresses = ''
    for i, emailAddress in enumerate(emailAddressesList, start=1):
        emailAddresses += f'{i}. {emailAddress}\n'

    update.message.reply_text(emailAddresses)
    return ConversationHandler.END


def verifyPasswordCommand(update: Update, context):
    update.message.reply_text('Введите пароль для проверки: ')
    return 'verifyPassword'


def verifyPassword(update: Update, context):
    user_input = update.message.text
    if re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()]).{8,}$', user_input):
        update.message.reply_text('Пароль сложный')
        return ConversationHandler.END
    else:
        update.message.reply_text('Пароль простой')
        return ConversationHandler.END


# Функция для установления SSH-подключения
def ssh_connect():
    host = os.getenv('HOST')
    port = int(os.getenv('PORT'))
    username = os.getenv('LOGIN')
    password = os.getenv('PASSWORD')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, username, password)

    return ssh


# Функция для выполнения команды по SSH
def execute_ssh_command(ssh, command):
    # Выполняем команду на удаленном сервере
    stdin, stdout, stderr = ssh.exec_command(command)
    # Читаем результат выполнения команды
    output = stdout.read().decode('utf-8')
    # Закрываем соединение
    ssh.close()

    return output


# Функция для получения информации о релизе
def get_release():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'cat /etc/*release')
    return output


# Функция для получения информации об архитектуре процессора, имени хоста системы и версии ядра
def get_uname():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'uname -a')
    return output


# Функция для получения информации о времени работы
def get_uptime():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'uptime')
    return output


# Функция для получения информации о состоянии файловой системы
def get_df():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'df -h')
    return output


# Функция для получения информации о состоянии оперативной памяти
def get_free():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'free -h')
    return output


# Функция для получения информации о производительности системы
def get_mpstat():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'mpstat')
    return output


# Функция для получения информации о работающих в данной системе пользователях
def get_w():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'w')
    return output


# Функция для получения последних 10 входов в систему
def get_auths():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'tail -n 10 /var/log/auth.log')
    return output


# Функция для получения последних 5 критических событий
def get_critical():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'tail -n 5 /var/log/syslog | grep -i "critical"')
    return output


# Функция для получения информации о запущенных процессах
def get_ps():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'ps aux | head -n 10')
    return output


# Функция для получения информации об используемых портах
def get_ss():
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'ss -tuln')
    return output


# Функиця для получения информации об установленных пакетах
def get_apt_list(update: Update, context):
    user_input = update.message.text
    ssh = ssh_connect()
    if user_input == 'all':
        output = execute_ssh_command(ssh, 'dpkg-query -l | tail -n 13')
        update.message.reply_text(output)
        return ConversationHandler.END
    else:
        package_name = user_input.strip()
        try:
            output = execute_ssh_command(ssh, f'dpkg-query -s {package_name}')
            update.message.reply_text(output)
        except:
            output = f"Пакет '{package_name}' не найден."
            update.message.reply_text(output)
        return ConversationHandler.END


# Функция для получения информации о запущенных сервисах
def get_services(update: Update, context):
    ssh = ssh_connect()
    output = execute_ssh_command(ssh, 'systemctl list-units --type=service | head -n 10')
    return output


# Функция обработки команды /get_release
def get_release_command(update: Update, context):
    update.message.reply_text(get_release())


# Функция обработки команды /get_uname
def get_uname_command(update: Update, context):
    update.message.reply_text(get_uname())


# Функция обработки команды /get_uptime
def get_uptime_command(update: Update, context):
    update.message.reply_text(get_uptime())


# Функция обработки команды /get_df
def get_df_command(update: Update, context):
    update.message.reply_text(get_df())


# Функция обработки команды /get_free
def get_free_command(update: Update, context):
    update.message.reply_text(get_free())


# Функция обработки команды /get_mpstat
def get_mpstat_command(update: Update, context):
    update.message.reply_text(get_mpstat())


# Функция обработки команды /get_w
def get_w_command(update: Update, context):
    update.message.reply_text(get_w())


# Функция обработки команды /get_auths
def get_auths_command(update: Update, context):
    update.message.reply_text(get_auths())


# Функция обработки команды /get_critical
def get_critical_command(update: Update, context):
    update.message.reply_text(get_critical())


# Функция обработки команды /get_ps
def get_ps_command(update: Update, context):
    update.message.reply_text(get_ps())


# Функция обработки команды /get_ss
def get_ss_command(update: Update, context):
    update.message.reply_text(get_ss())


# Функция для обработки команды /get_apt_list
def get_apt_list_command(update: Update, context):
    update.message.reply_text(
        'Введите all для вывода всех пакетов\nЕсли нужно найти конкретный пакет, введите его название ')
    return 'get_apt_list'


# Функция обработки команды /get_services
def get_services_command(update: Update, context):
    update.message.reply_text(get_services())


def echo(update: Update, context):
    update.message.reply_text(update.message.text)



def main():
    updater = Updater(TOKEN, use_context=True)

    # Получаем диспетчер для регистрации обработчиков
    dp = updater.dispatcher

    # обработчик номеров
    convHandlerFindPhoneNumbers = ConversationHandler(
        entry_points=[CommandHandler('findPhoneNumbers', findPhoneNumbersCommand)],
        states={
            'findPhoneNumbers': [MessageHandler(Filters.text & ~Filters.command, findPhoneNumbers)],
        },
        fallbacks=[]
    )

    # обработчик почты
    convHandlerFindEmailAddresses = ConversationHandler(
        entry_points=[CommandHandler('findEmailAddresses', findEmailAddressesCommand)],
        states={'findEmailAddresses': [MessageHandler(Filters.text & ~Filters.command, findEmailAddresses)]},
        fallbacks=[]
    )

    # обработчик пароля
    convHandlerVerifyPassword = ConversationHandler(
        entry_points=[CommandHandler('verifyPassword', verifyPasswordCommand)],
        states={
            'verifyPassword': [MessageHandler(Filters.text & ~Filters.command, verifyPassword)]
        },
        fallbacks=[]
    )

    convHandlerGetAptLists = ConversationHandler(
        entry_points=[CommandHandler('get_apt_list', get_apt_list_command)],
        states={'get_apt_list': [MessageHandler(Filters.text & ~Filters.command, get_apt_list)]},
        fallbacks=[]
    )

    # Регистрируем обработчики команд
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", helpCommand))
    dp.add_handler(convHandlerFindPhoneNumbers)
    dp.add_handler(convHandlerFindEmailAddresses)
    dp.add_handler(convHandlerVerifyPassword)
    dp.add_handler(convHandlerGetAptLists)
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))
    dp.add_handler(CommandHandler("get_release", get_release_command))
    dp.add_handler(CommandHandler("get_uname", get_uname_command))
    dp.add_handler(CommandHandler("get_uptime", get_uptime_command))
    dp.add_handler(CommandHandler("get_df", get_df_command))
    dp.add_handler(CommandHandler("get_free", get_free_command))
    dp.add_handler(CommandHandler("get_mpstat", get_mpstat_command))
    dp.add_handler(CommandHandler("get_w", get_w_command))
    dp.add_handler(CommandHandler("get_auths", get_auths_command))
    dp.add_handler(CommandHandler("get_critical", get_critical_command))
    dp.add_handler(CommandHandler("get_ps", get_ps_command))
    dp.add_handler(CommandHandler("get_ss", get_ss_command))
    dp.add_handler(CommandHandler("get_services", get_services_command))
    # Запускаем бота
    updater.start_polling()
    # Останавливаем бота при нажатии Ctrl+C
    updater.idle()


if __name__ == '__main__':
    main()
