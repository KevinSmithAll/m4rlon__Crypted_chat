import socket
from threading import Thread
import rsa
from cryptography.fernet import Fernet


class ChatServer:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host  # ip-адрес сервера
        self.port = port  # порт сервера
        self.clients = []  # список подключенных клиентов
        self.client_keys = []  # cписок ключей для шифрования сообщений по каждому клиенту
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)  # создаем сокет
        self.sock.bind((host, port))  # привязка ip и порта
        print(f'Запущен сервер {host}:{port}')

    def listen(self):
        """
        Функция для прослушивания входящих подключений
        """
        while True:  # бесконечный цикл
            self.sock.listen()  # слушаем входящие подключения
            print(f'Ожидаем подключения')
            conn, addr = self.sock.accept()  # принимаем соединение
            print(f'Connected with {addr}')

            self.clients.append(conn)  # обновленный список клиентов
            # создаем новый поток для обработки вновь присоедененного клиента
            Thread(target=self.handle_client, args=(conn,)).start()

    def handle_client(self, client_socket) -> None:
        """
        Функция-обработчик каждого клиента
        Состоит из следующих этапов:
        1) Получаем ник и публичный ключ клиента
        2) Генерация закрытого ключа симметричного алгоритма Fernet
        3) Шифрование ключа симметричного алгоритма Fernet открытым ключом RSA клиента
        4) Создание шифратора сервера
        5) Передача клиенту зашифрованного ключа симметричного алгоритма Fernet
        Параметры:
            - Подключенный клиент
        """
        # Получаем ник клиента
        client_nick = client_socket.recv(1024).decode('utf-8')
        # публичный ключ клиента
        client_public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))
        # генерация закрытого ключа симметричного алгоритма Fernet
        key = Fernet.generate_key()
        # шифрование ключа симметричного алгоритма Fernet открытым ключом RSA клиента
        crypted_key = rsa.encrypt(message=key, pub_key=client_public_key)
        # создание шифратора сервера
        fernet = Fernet(key)
        # передача клиенту зашифрованного ключа симметричного алгоритма Fernet
        client_socket.sendall(crypted_key)
        self.client_keys.append(key)  # запись ключа в массив клиентских ключей
        print(
            f'С пользователем "{client_nick}" установлено защищенное соединение')
        try:
            # передача сообщения всем клиентам о подключении очередного клиента
            self.broadcast_all(f"Пользователь {client_nick} подключился")
        except Exception:
            pass
        while True:  # бесконечный цикл
            try:
                # получение сообщения от клиента
                data = client_socket.recv(1024).decode('utf-8')
                # расшифровка сообщения от клиента ключом Fernet
                decrypted_data = fernet.decrypt(data.encode()).decode()
                if not data:
                    break
                # отправка сообщения всем клиентам
                self.broadcast(decrypted_data, client_socket, client_nick)
            # если клиент отключился
            except ConnectionResetError:
                print(f'Пользователь "{client_nick}" отключился.')
                # удаление клиента из списка подключенных клиентов
                self.clients.remove(client_socket)
                # удаление ключа клиента из списка ключей
                self.client_keys.remove(key)
                # отправка сообщения всем клиентам о отключении клиента
                self.broadcast_all(f"Пользователь '{client_nick}' отключился")
                break

    def broadcast(self, message, sender, nickname):
        """
        Функция для отправки сообщения всем клиентам
        Параметры:
            - Сообщение
            - Отправитель
            - Ник отправителя
        """
        # цикл по всем клиентам, кроме отправителя
        for j, client in enumerate(self.clients):
            if client != sender:
                try:
                    # загрузка ключа для конкретного клиента
                    this_key = self.client_keys[j]
                    # создание шифратора для конкретного клиента
                    this_fernet = Fernet(this_key)
                    # шифрование сообщения для конкретного клиента
                    msg_for_client = this_fernet.encrypt(
                        f"{nickname} отправил: {message}".encode())
                    # отправка сообщения конкретному клиенту
                    client.sendall(msg_for_client)
                # если клиент отключился
                except BrokenPipeError:
                    self.clients.remove(client)

    def broadcast_all(self, message):
        """
        Функция для оповещения всех клиентов о событии
        Параметры:
            - Сообщение
        """
        # перебор всех клиентов
        for j, client in enumerate(self.clients):
            try:
                # загрузка ключа для конкретного клиента
                this_key = self.client_keys[j]
                # создание шифратора для конкретного клиента
                this_fernet = Fernet(this_key)
                # шифрование сообщения для конкретного клиента
                client.sendall(this_fernet.encrypt(message.encode()))
            # если клиент отключился
            except BrokenPipeError:
                self.clients.remove(client)

    def close_server(self):
        """
        Функция аварийного отключения сервера
        """
        # закрытие всех соединений
        self.sock.close()


if __name__ == '__main__':
    server = ChatServer()
    try:
        server.listen()
    except KeyboardInterrupt:
        server.close_server()
