import socket
from threading import Thread
import rsa
from cryptography.fernet import Fernet
#


class ChatClient:
    def __init__(self, nickname: str, host='127.0.0.1', port=12345):
        self.nickname = nickname  # никнейм клиента
        self.host = host  # IP-адрес сервера
        self.port = port  # порт сервера
        # Создание tcp/ip сокета
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))  # Подключение к серверу
        print(f'Connected to server at {host}:{port}')
        # Отправка никнейма на сервер
        self.sock.sendall(self.nickname.encode('utf-8'))
        self.create_RSA()  # создание асимметричного шифрования
        self.send_key()  # отправка публичного ключа на сервер
        # получение зашифрованного ключа симметричного шифрования
        crypted_key_fernet = self.sock.recv(1024)
        # расшифровка ключа симметричного шифрования своим приватным ключом
        self.key_fernet = rsa.decrypt(crypted_key_fernet, self.private_key)
        # создание шифратора/дешифратора симметричного шифрования
        self.fernet = Fernet(self.key_fernet)
        print(f'Установлено защищенное соединение с сервером')

    def create_RSA(self):
        """
        Функция для создания пары ключей для асимметричного шифрования
        """
        # создание ключей для асимметричного шифрования (открытого и приватного)
        self.public_key, self.private_key = rsa.newkeys(1024)
        print('Защитные ключи созданы')

    def send_key(self):
        """
        Функция для отправки публичного ключа на сервер
        """
        try:
            # отправка публичного ключа на сервер
            self.sock.sendall(self.public_key.save_pkcs1('PEM'))
        except Exception:
            print('Ошибка отправки ключа')

    def send_message(self):
        """
        Функция для отправки сообщений на сервер
        """
        # бесконечный цикл отправки сообщений на сервер
        while True:
            # Сообщение для отправки на сервер
            message = input('Введите сообщение для отправки:\n')
            # Проверка на выход из чата
            if message == 'exit':
                break
            # Передача зашифрованного сообщения на сервер
            self.sock.sendall(self.fernet.encrypt(message.encode('utf-8')))

    def receive_message(self):
        """
        Функция для получения сообщений от сервера
        """
        # бесконечный цикл получения сообщений от сервера
        while True:
            # получение зашифрованного сообщения от сервера
            data = self.sock.recv(1024)
            # расшифровка сообщения
            decrypted_data = self.fernet.decrypt(data).decode('utf-8')
            if not data:
                break
            print(decrypted_data)

    def start_chat(self):
        """
        Функция для запуска чата
        """
        # запуск потоков для отправки и получения сообщений
        Thread(target=self.receive_message).start()
        # отправка сообщений на сервер
        self.send_message()

    def close_connection(self):
        """
        Функция для закрытия соединения с сервером
        """
        self.sock.close()


if __name__ == '__main__':
    # Создания клиента
    client = ChatClient(nickname='Решала')
    try:
        client.start_chat()
    except KeyboardInterrupt:
        client.close_connection()
