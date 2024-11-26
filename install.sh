#!/bin/bash

# Название службы
SERVICE_NAME="awg_bot"

# Цветовые коды для сообщений
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
BLUE=$'\033[0;34m'
NC=$'\033[0m' # No Color

# Функция для отображения спиннера с захватом ошибок
run_with_spinner() {
    local description="$1"
    shift
    local cmd="$@"

    # Создаём временные файлы для вывода и ошибок
    local stdout_temp=$(mktemp)
    local stderr_temp=$(mktemp)

    # Запуск команды в фоновом режиме с сохранением вывода
    eval "$cmd" >"$stdout_temp" 2>"$stderr_temp" &
    local pid=$!

    # Спиннер символы
    local spinner='|/-\'
    local i=0

    # Печать описания и начального символа спиннера
    echo -ne "\n${BLUE}${description}... ${spinner:i++%${#spinner}:1}${NC}"

    # Пока процесс выполняется, отображаем спиннер
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${BLUE}${description}... ${spinner:i++%${#spinner}:1}${NC}"
        sleep 0.1
    done

    # Проверка статуса команды
    wait "$pid"
    local status=$?
    if [ $status -eq 0 ]; then
        printf "\r${GREEN}${description}... Done!${NC}\n"
        # Удаляем временные файлы
        rm -f "$stdout_temp" "$stderr_temp"
    else
        printf "\r${RED}${description}... Failed!${NC}\n"
        echo -e "${RED}Ошибка при выполнении команды: $cmd${NC}"
        echo -e "${RED}Вывод ошибки:${NC}"
        cat "$stderr_temp"
        # Удаляем временные файлы
        rm -f "$stdout_temp" "$stderr_temp"
        exit 1
    fi
}

# Функция для обновления и очистки системы
update_and_clean_system() {
    run_with_spinner "Обновление системы" "sudo apt-get update -qq && sudo apt-get upgrade -y -qq"
    run_with_spinner "Очистка системы от ненужных пакетов" "sudo apt-get autoclean -qq && sudo apt-get autoremove --purge -y -qq"
}

# Функция для проверки наличия Python 3.11
check_python() {
    if command -v python3.11 &>/dev/null; then
        echo -e "\n${GREEN}Python 3.11 установлен.${NC}"
    else
        echo -e "\n${RED}Python 3.11 не установлен или версия не подходит.${NC}"
        read -p "Установить Python 3.11? (y/n): " install_python
        if [[ "$install_python" == "y" || "$install_python" == "Y" ]]; then
            # Удаляем опцию -qq из add-apt-repository
            run_with_spinner "Установка Python 3.11" "sudo apt-get install software-properties-common -y && sudo add-apt-repository ppa:deadsnakes/ppa -y && sudo apt-get update -qq && sudo apt-get install python3.11 python3.11-venv python3.11-dev -y -qq"
            if ! command -v python3.11 &>/dev/null; then
                echo -e "\n${RED}Не удалось установить Python 3.11. Завершение работы.${NC}"
                exit 1
            fi
            echo -e "\n${GREEN}Python 3.11 успешно установлен.${NC}"
        else
            echo -e "\n${RED}Установка Python 3.11 обязательна. Завершение работы.${NC}"
            exit 1
        fi
    fi
}

# Функция для установки системных зависимостей
install_dependencies() {
    run_with_spinner "Установка системных зависимостей" "sudo apt-get install qrencode net-tools iptables resolvconf git -y -qq"
}

# Функция для установки и настройки needrestart
install_and_configure_needrestart() {
    run_with_spinner "Установка needrestart" "sudo apt-get install needrestart -y -qq"

    # Настройка needrestart для автоматической перезагрузки служб без подтверждения
    sudo sed -i 's/^#\?\(nrconf{restart} = "\).*$/\1a";/' /etc/needrestart/needrestart.conf
    grep -q 'nrconf{restart} = "a";' /etc/needrestart/needrestart.conf || echo 'nrconf{restart} = "a";' | sudo tee -a /etc/needrestart/needrestart.conf >/dev/null 2>&1
}

# Функция для клонирования репозитория
clone_repository() {
    if [ ! -d "awg_bot" ]; then
        run_with_spinner "Клонирование репозитория" "git clone https://github.com/JB-SelfCompany/awg_bot.git >/dev/null 2>&1"
        if [ $? -ne 0 ]; then
            echo -e "\n${RED}Ошибка при клонировании репозитория. Завершение работы.${NC}"
            exit 1
        fi
        echo -e "\n${GREEN}Репозиторий успешно клонирован.${NC}"
    else
        echo -e "\n${YELLOW}Репозиторий уже существует. Пропуск клонирования.${NC}"
    fi
    cd awg_bot || { echo -e "\n${RED}Не удалось перейти в директорию awg_bot. Завершение работы.${NC}"; exit 1; }
}

# Функция для настройки виртуального окружения
setup_venv() {
    if [ -d "myenv" ]; then
        echo -e "\n${YELLOW}Виртуальное окружение уже существует. Пропуск создания и установки зависимостей.${NC}"
    else
        run_with_spinner "Настройка виртуального окружения" "python3.11 -m venv myenv && source myenv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt && deactivate"
        echo -e "\n${GREEN}Виртуальное окружение настроено и зависимости установлены.${NC}"
    fi
}

# Функция для установки прав на скрипты
set_permissions() {
    echo -e "\n${BLUE}Установка прав на скрипты...${NC}"

    # Вывод текущей директории и списка .sh файлов
    echo "Текущая директория: $(pwd)"
    echo "Найденные .sh файлы:"
    find . -type f -name "*.sh" -print

    # Поиск всех .sh файлов и установка прав на выполнение
    find . -type f -name "*.sh" -exec chmod +x {} \; 2>chmod_error.log

    # Проверка успешности команды
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Права на скрипты установлены.${NC}"
    else
        echo -e "${RED}Ошибка при установке прав на скрипты. Проверьте файл chmod_error.log для деталей.${NC}"
        cat chmod_error.log
        rm -f chmod_error.log
        exit 1
    fi

    # Удаление временного файла ошибок
    rm -f chmod_error.log
}

# Функция для запуска бота для инициализации
initialize_bot() {
    echo -e "\n${BLUE}Запуск бота для инициализации...${NC}"

    # Переход в директорию awg
    cd awg || { echo -e "\n${RED}Не удалось перейти в директорию awg. Завершение работы.${NC}"; exit 1; }

    # Запуск бота в фоновом режиме с подключением stdin к терминалу
    ../myenv/bin/python3.11 bot_manager.py < /dev/tty &
    BOT_PID=$!

    echo -e "${YELLOW}Бот запущен с PID $BOT_PID. Пожалуйста, завершите инициализацию через Telegram.${NC}"

    # Ожидание создания файла настройки (например, files/setting.ini)
    while [ ! -f "files/setting.ini" ]; do
        sleep 2
        # Проверка, запущен ли бот
        if ! kill -0 "$BOT_PID" 2>/dev/null; then
            echo -e "\n${RED}Бот завершил работу до завершения инициализации. Завершение установки.${NC}"
            exit 1
        fi
    done

    echo -e "\n${GREEN}Инициализация завершена. Остановка бота...${NC}"
    kill "$BOT_PID"
    wait "$BOT_PID" 2>/dev/null

    echo -e "${GREEN}Бот остановлен.${NC}"

    # Возврат в корневую директорию awg_bot
    cd ..
}

# Функция для создания системной службы
create_service() {
    run_with_spinner "Создание системной службы" "echo '[Unit]
Description=AWG Telegram Bot
After=network.target

[Service]
User=$USER
WorkingDirectory=$(pwd)/awg
ExecStart=$(pwd)/myenv/bin/python3.11 bot_manager.py
Restart=always

[Install]
WantedBy=multi-user.target' | sudo tee /etc/systemd/system/$SERVICE_NAME.service >/dev/null 2>&1"

    run_with_spinner "Перезагрузка демонов systemd" "sudo systemctl daemon-reload -qq"

    run_with_spinner "Запуск службы $SERVICE_NAME" "sudo systemctl start $SERVICE_NAME -qq"

    run_with_spinner "Включение службы $SERVICE_NAME при загрузке системы" "sudo systemctl enable $SERVICE_NAME -qq"

    # Проверка статуса службы
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "\n${GREEN}Служба $SERVICE_NAME успешно запущена.${NC}"
    else
        echo -e "\n${RED}Не удалось запустить службу $SERVICE_NAME. Проверьте логи с помощью команды:${NC}"
        echo "sudo systemctl status $SERVICE_NAME"
    fi
}

# Функция для меню управления службой
service_menu() {
    while true; do
        echo -e "\n=== Управление службой $SERVICE_NAME ==="
        sudo systemctl status "$SERVICE_NAME" | grep -E "Active:|Loaded:"

        echo -e "\n1. Остановить службу"
        echo "2. Перезапустить службу"
        echo "3. Удалить службу"
        echo "4. Выйти"
        read -p "Выберите действие: " action

        case $action in
            1)
                run_with_spinner "Остановка службы" "sudo systemctl stop $SERVICE_NAME -qq"
                echo -e "\n${GREEN}Служба остановлена.${NC}"
                ;;
            2)
                run_with_spinner "Перезапуск службы" "sudo systemctl restart $SERVICE_NAME -qq"
                echo -e "\n${GREEN}Служба перезапущена.${NC}"
                ;;
            3)
                run_with_spinner "Удаление службы" "sudo systemctl stop $SERVICE_NAME -qq && sudo systemctl disable $SERVICE_NAME -qq && sudo rm /etc/systemd/system/$SERVICE_NAME.service && sudo systemctl daemon-reload -qq"
                echo -e "\n${GREEN}Служба удалена.${NC}"
                ;;
            4)
                echo -e "\n${BLUE}Выход из меню управления.${NC}"
                break
                ;;
            *)
                echo -e "\n${RED}Некорректный ввод. Пожалуйста, выберите действительный вариант.${NC}"
                ;;
        esac
    done
}

# Главная функция установки
install_bot() {
    update_and_clean_system
    check_python
    install_dependencies
    install_and_configure_needrestart
    clone_repository
    setup_venv
    set_permissions
    initialize_bot
    create_service
}

# Главная логика
main() {
    echo -e "=== Установка AWG Telegram Bot ==="
    echo -e "Начало установки..."

    # Проверка наличия службы
    if systemctl list-units --type=service --all | grep -q "$SERVICE_NAME.service"; then
        echo -e "\n${YELLOW}Бот уже установлен в системе.${NC}"
        service_menu
    else
        echo -e "\n${GREEN}Бот не установлен.${NC}"
        install_bot
        echo -e "\n${GREEN}Установка завершена. Перейдём к управлению службой.${NC}"
        service_menu
    fi
}

# Запуск основной функции
main
