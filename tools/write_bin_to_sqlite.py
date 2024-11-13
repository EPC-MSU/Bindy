import sqlite3
from typing import List


class User:
    """
    User class.
    """

    AES_KEY_LENGTH: int = 16
    AUTH_DATA_LENGTH: int = 32
    
    def __init__(self, uuid: List[int], name: str, role: int, key: List[int]) -> None:
        """
        :param uuid: unique identifier;
        :param name: user name;
        :param role: user role;
        :param key: unique key.
        """

        self._key: List[int] = key
        self._name: str = name
        self._role: int = role
        self._uuid: List[int] = uuid
    
    def __str__(self) -> str:
        """
        :return: text representation.
        """

        return f"{self._uuid}, {self._name}, {self._role}, {self._key}"

    @property
    def key(self) -> List[int]:
        """
        :return: key.
        """

        return self._key

    @property
    def name(self) -> str:
        """
        :return: user name.
        """

        return self._name
    
    @property
    def role(self) -> int:
        """
        :return: user role.
        """

        return self._role

    @classmethod
    def create_user_from_data(cls, data: bytes, user_role: int) -> "User":
        """
        :param data: bytes from which to extract user data;
        :param user_role: user role.
        :return: new user from given data.
        """

        user_data = data[:User.size()]
        uuid = User.get_uuid_from_bin_data(user_data)
        user_name = User.get_user_name_from_bin_data(user_data)
        key = User.get_key_from_bin_data(user_data)
        return User(uuid, user_name, user_role, key)
    
    @classmethod
    def size(cls) -> int:
        return cls.AES_KEY_LENGTH + cls.AUTH_DATA_LENGTH

    def convert_key_to_bytes(self) -> bytes:
        """
        :return: key as bytes.
        """

        return b"".join(number.to_bytes(1, "big") for number in self._key)

    def convert_uuid_to_bytes(self) -> bytes:
        """
        :return: UUID as bytes.
        """

        return b"".join(number.to_bytes(1, "big") for number in self._uuid)

    @staticmethod
    def get_key_from_bin_data(data: bytes) -> List[int]:
        """
        :param data: bytes from which to extract user data.
        :return: key.
        """

        return [byte for byte in data[User.AUTH_DATA_LENGTH:]]

    @staticmethod
    def get_user_name_from_bin_data(data: bytes) -> str:
        """
        :param data: bytes from which to extract user data.
        :return: user name.
        """

        user_data = data[:User.size()]
        raw_uuid = user_data[:User.AUTH_DATA_LENGTH]
        return raw_uuid.decode("utf-8")

    @staticmethod
    def get_uuid_from_bin_data(data: bytes) -> List[int]:
        """
        :param data: bytes from which to extract user data.
        :return: UUID.
        """

        return [byte for byte in data[:User.AUTH_DATA_LENGTH]]


def create_table(connection) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute("CREATE TABLE Users (uuid TEXT UNIQUE NOT NULL PRIMARY KEY, name TEXT NOT NULL, role INTEGER NOT NULL, key BLOB (16) NOT NULL UNIQUE);")
        cursor.execute("CREATE TRIGGER SingleMasterInsert BEFORE INSERT ON Users FOR EACH ROW WHEN NEW.role = 1 BEGIN SELECT RAISE (ABORT, 'master already exists') WHERE EXISTS(SELECT 1 FROM Users WHERE role = 1); END;")
        cursor.execute("CREATE TRIGGER SingleMasterUpdate BEFORE UPDATE OF role ON Users FOR EACH ROW WHEN NEW.role = 1  BEGIN SELECT RAISE (ABORT, 'master already exists') WHERE EXISTS(SELECT 1 FROM Users WHERE role = 1); END;")
        connection.commit()
    except Exception:
        print("'Users' table has already been created in the database")


def main() -> None:
    users = read_users_from_bin_file("keyfile.bin")
    save_users_to_database("keyfile.sqlite", users)


def read_users_from_bin_file(filename: str) -> List[User]:
    """
    :param filename: the name of the binary file that contains user data in the old format.
    :return: list with user data.
    """

    with open(filename, "rb") as file:
        data = file.read()

    users = []
    while data:
        user_role = 1 if not len(users) else 2
        user = User.create_user_from_data(data, user_role)
        users.append(user)
        data = data[User.size():]

    return users


def save_users_to_database(filename: str, users: List[User]) -> None:
    """
    :param filename: database file where user data should be saved;
    :param users: list with user data.
    """

    connection = sqlite3.connect(filename)
    create_table(connection)

    cursor = connection.cursor()
    for user in users:
        print(user)
        cursor.execute("INSERT INTO Users (uuid, name, role, key) VALUES (?, ?, ?, ?)",
                       (user.convert_uuid_to_bytes(), user.name, user.role, user.convert_key_to_bytes()))
    connection.commit()

    connection.close()


if __name__ == "__main__":
    main()
