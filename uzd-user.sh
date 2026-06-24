#!/bin/bash
# ============================================================
#  Керування доступами до scriber.akesosystems.com
#  Покласти на сервер і зробити виконуваним (інструкція в чаті).
#
#  Використання:
#    uzd-user list                    — показати всіх користувачів
#    uzd-user add  логін пароль      — додати нового користувача
#    uzd-user pass логін новийпароль — змінити пароль
#    uzd-user del  логін             — ЗАБРАТИ доступ (миттєво)
# ============================================================
FILE=/etc/nginx/.htpasswd

case "$1" in
  list)
    echo "Користувачі з доступом до сайту:"
    cut -d: -f1 "$FILE"
    exit 0
    ;;
  add|pass)
    if [ -z "$2" ] || [ -z "$3" ]; then echo "Треба: uzd-user $1 логін пароль"; exit 1; fi
    htpasswd -b "$FILE" "$2" "$3"
    ;;
  del)
    if [ -z "$2" ]; then echo "Треба: uzd-user del логін"; exit 1; fi
    htpasswd -D "$FILE" "$2"
    ;;
  *)
    echo "Команди: list | add логін пароль | pass логін новийпароль | del логін"
    exit 1
    ;;
esac

systemctl reload nginx && echo "Готово, зміни вже діють."
