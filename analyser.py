from collections import Counter

# Список найденных IP
suspicious_ips = []

# Открываем файл
with open('ssh_bruteforce/mock_auth.log', 'r') as file:
    for line in file:
        # Проверяем, есть ли в строке нужная ошибка
        if "Failed password" in line:
            
            # Разбиваем строку на список слов по пробелам
            words = line.split()
            
            # Находим, под каким номером (индексом) идет слово "from"
            index_of_from = words.index("from")
            
            # IP-адрес — это следующее слово после "from" (индекс + 1)
            ip = words[index_of_from + 1]
            
            # Добавляем IP в список
            suspicious_ips.append(ip)

# Считаем сколько раз встретился каждый IP
ip_counts = Counter(suspicious_ips)

print("Результат анализа логов")
for ip, count in ip_counts.most_common(10):
    print(f"IP: {ip} | Попыток брутфорса: {count}")