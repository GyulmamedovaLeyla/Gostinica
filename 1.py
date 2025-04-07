import psycopg2
import tkinter as tk
from tkinter import messagebox
from datetime import datetime, timedelta

DB_CONFIG = {
    "dbname": "HotelManagement",
    "user": "postgres",
    "password": "123456",
    "host": "localhost",
    "port": "5433"
}


def execute_query(query, params=(), fetchone=False, fetchall=False, commit=False):
    with psycopg2.connect(**DB_CONFIG) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if fetchone:
                return cur.fetchone()
            if fetchall:
                return cur.fetchall()
            if commit:
                conn.commit()


def get_user(login):
    return execute_query(
        "SELECT ID, Parol, rolid, Zablokirovan, Parol_smenen, Imya, Familiya, Data_last_login, Failed_attempts FROM POLZOVATELI WHERE Login = %s",
        (login,), fetchone=True
    )


def update_last_login(user_id):
    """Обновляет время последнего входа и сбрасывает счетчик попыток"""
    execute_query(
        "UPDATE POLZOVATELI SET Data_last_login = %s, Failed_attempts = 0 WHERE ID = %s",
        (datetime.now(), user_id),
        commit=True
    )


def increment_failed_attempts(login):
    """счетчик неудачных попыток входа"""
    execute_query(
        "UPDATE POLZOVATELI SET Failed_attempts = Failed_attempts + 1 WHERE Login = %s",
        (login,),
        commit=True
    )
    user = get_user(login)
    if user and user[8] >= 3:
        execute_query(
            "UPDATE POLZOVATELI SET Zablokirovan = TRUE WHERE Login = %s",
            (login,),
            commit=True
        )


def unblock_user(user_id):
    execute_query(
        "UPDATE POLZOVATELI SET Zablokirovan = FALSE, Failed_attempts = 0 WHERE ID = %s",
        (user_id,),
        commit=True
    )


def authenticate(login, password):
    if not login or not password:
        return None, "Введите логин и пароль."

    user = get_user(login)
    if not user:
        return None, "Неверный логин или пароль."

    user_id, stored_password, role, blocked, password_changed, name, surname, last_login, failed_attempts = user

    # Автоблокировка при неактивности более месяца
    if last_login and (datetime.now() - last_login) > timedelta(days=30):
        execute_query(
            "UPDATE POLZOVATELI SET Zablokirovan = TRUE WHERE ID = %s",
            (user_id,),
            commit=True
        )
        blocked = True

    if blocked:
        return None, "Вы заблокированы. Обратитесь к администратору."

    if password != stored_password:
        increment_failed_attempts(login)
        return None, "Неверный логин или пароль."

    update_last_login(user_id)
    return role, user_id, name, surname, password_changed


class ChangePasswordWindow:
    """Окно смены пароля (теперь на весь экран)"""

    def __init__(self, user_id, callback):
        self.user_id = user_id
        self.callback = callback
        self.window = tk.Tk()
        self.window.title("Смена пароля")
        self.window.state('zoomed')

        for i in range(5):
            self.window.grid_rowconfigure(i, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_columnconfigure(1, weight=2)

        big_font = ('Arial', 16)
        big_button_font = ('Arial', 16, 'bold')
        padding = {'padx': 50, 'pady': 20}

        tk.Label(self.window, text="Смена пароля", font=('Arial', 20, 'bold')).grid(row=0, column=0, columnspan=2,
                                                                                    pady=40)

        tk.Label(self.window, text="Текущий пароль:", font=big_font).grid(row=1, column=0, sticky='e', **padding)
        self.current_password = tk.Entry(self.window, font=big_font)
        self.current_password.grid(row=1, column=1, sticky='ew', **padding)

        tk.Label(self.window, text="Новый пароль:", font=big_font).grid(row=2, column=0, sticky='e', **padding)
        self.new_password = tk.Entry(self.window, font=big_font)
        self.new_password.grid(row=2, column=1, sticky='ew', **padding)

        tk.Label(self.window, text="Подтвердите пароль:", font=big_font).grid(row=3, column=0, sticky='e', **padding)
        self.confirm_password = tk.Entry(self.window, font=big_font)
        self.confirm_password.grid(row=3, column=1, sticky='ew', **padding)

        button_frame = tk.Frame(self.window)
        button_frame.grid(row=4, column=0, columnspan=2, pady=40)

        tk.Button(button_frame, text="Изменить пароль", command=self.change_password,
                  font=big_button_font, padx=20, pady=10).pack(side=tk.TOP, fill=tk.X)

    def change_password(self):
        current = self.current_password.get()
        new = self.new_password.get()
        confirm = self.confirm_password.get()

        if not current or not new or not confirm:
            messagebox.showerror("Ошибка", "Все поля обязательны для заполнения")
            return

        user = execute_query(
            "SELECT Parol FROM POLZOVATELI WHERE ID = %s",
            (self.user_id,), fetchone=True
        )
        if not user or user[0] != current:
            messagebox.showerror("Ошибка", "Неверный текущий пароль")
            return

        if new != confirm:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return

        execute_query(
            "UPDATE POLZOVATELI SET Parol = %s, Parol_smenen = TRUE WHERE ID = %s",
            (new, self.user_id),
            commit=True
        )

        messagebox.showinfo("Успех", "Пароль успешно изменен")
        self.window.destroy()
        self.callback()


class UserWelcomeWindow:
    """Окно приветствия пользователя"""

    def __init__(self, user_id, name, surname):
        self.window = tk.Tk()
        self.window.title("Добро пожаловать")
        self.window.state('zoomed')

        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_rowconfigure(1, weight=0)
        self.window.grid_rowconfigure(2, weight=0)
        self.window.grid_rowconfigure(3, weight=1)
        self.window.grid_columnconfigure(0, weight=1)

        welcome_label = tk.Label(
            self.window,
            text=f"Приветствуем, {name} {surname}",
            font=("Arial", 14)
        )
        welcome_label.grid(row=1, column=0, pady=40, sticky='nsew')

        button_frame = tk.Frame(self.window)
        button_frame.grid(row=2, column=0, sticky='ew', padx=100, pady=10)
        button_frame.grid_columnconfigure(0, weight=1)

        logout_btn = tk.Button(
            button_frame,
            text="Выйти",
            command=self.logout,
            font=("Arial", 12)
        )
        logout_btn.grid(row=0, column=0, sticky='ew', ipady=10)

        self.window.mainloop()

    def logout(self):
        self.window.destroy()
        HotelApp()

class HotelApp:
    """Главное окно авторизации"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Авторизация")
        self.root.state('zoomed')
        self.root.minsize(400, 300)

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure([0, 1, 2, 3, 4], weight=1)

        tk.Label(self.root, text="Логин", font=("Arial", 12)).grid(row=0, column=0, pady=5, sticky="nsew")
        self.login_entry = tk.Entry(self.root, font=("Arial", 12))
        self.login_entry.grid(row=1, column=0, pady=5, padx=20, sticky="nsew")

        tk.Label(self.root, text="Пароль", font=("Arial", 12)).grid(row=2, column=0, pady=5, sticky="nsew")
        self.password_entry = tk.Entry(self.root, font=("Arial", 12))
        self.password_entry.grid(row=3, column=0, pady=5, padx=20, sticky="nsew")

        tk.Button(self.root, text="Войти", command=self.on_submit, font=("Arial", 12)).grid(row=4, column=0, pady=10,
                                                                                            sticky="nsew")

        self.root.mainloop()

    def on_submit(self):
        login = self.login_entry.get()
        password = self.password_entry.get()
        result = authenticate(login, password)

        if result[0] is None:
            messagebox.showinfo("Ошибка", result[1])
            return

        role, user_id, name, surname, password_changed = result
        role_name = "Администратор" if role == 2 else "Пользователь"
        messagebox.showinfo("Успех", f"Вы вошли как {role_name}")

        self.root.destroy()

        if role == 2:
            AdminWindow()
        else:
            if not password_changed:
                ChangePasswordWindow(user_id, lambda: UserWelcomeWindow(user_id, name, surname))
            else:
                UserWelcomeWindow(user_id, name, surname)


class AdminWindow:
    """Окно администратора"""

    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Администрирование")
        self.window.state('zoomed')
        self.window.minsize(600, 400)

        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_rowconfigure([0, 1, 2], weight=1)

        tk.Button(self.window, text="Добавить пользователя", command=self.add_user, font=("Arial", 14)).grid(row=0,
                                                                                                             column=0,
                                                                                                             padx=20,
                                                                                                             pady=10,
                                                                                                             sticky="nsew")
        tk.Button(self.window, text="Управление пользователями", command=self.manage_users, font=("Arial", 14)).grid(
            row=1, column=0, padx=20, pady=10, sticky="nsew")
        tk.Button(self.window, text="Выйти", command=self.logout, font=("Arial", 14)).grid(row=2, column=0, padx=20,
                                                                                           pady=10, sticky="nsew")

        self.window.mainloop()

    def add_user(self):
        AddUserWindow()

    def manage_users(self):
        ManageUsersWindow(self.window)

    def logout(self):
        self.window.destroy()
        HotelApp()


class AddUserWindow:
    """Окно добавления нового пользователя"""

    def __init__(self):
        self.window = tk.Toplevel()
        self.window.title("Добавить пользователя")
        self.window.state('zoomed')

        self.window.grid_columnconfigure(1, weight=1)
        for i in range(7):
            self.window.grid_rowconfigure(i, weight=1)

        font_size = 14
        pad_y = 10
        pad_x = 20

        tk.Label(self.window, text="Имя", font=("Arial", font_size)).grid(
            row=0, column=0, pady=pad_y, padx=pad_x, sticky="w")
        self.name_entry = tk.Entry(self.window, font=("Arial", font_size))
        self.name_entry.grid(row=0, column=1, pady=pad_y, padx=pad_x, sticky="ew")

        tk.Label(self.window, text="Фамилия", font=("Arial", font_size)).grid(
            row=1, column=0, pady=pad_y, padx=pad_x, sticky="w")
        self.surname_entry = tk.Entry(self.window, font=("Arial", font_size))
        self.surname_entry.grid(row=1, column=1, pady=pad_y, padx=pad_x, sticky="ew")

        tk.Label(self.window, text="Логин", font=("Arial", font_size)).grid(
            row=2, column=0, pady=pad_y, padx=pad_x, sticky="w")
        self.login_entry = tk.Entry(self.window, font=("Arial", font_size))
        self.login_entry.grid(row=2, column=1, pady=pad_y, padx=pad_x, sticky="ew")

        tk.Label(self.window, text="Пароль", font=("Arial", font_size)).grid(
            row=3, column=0, pady=pad_y, padx=pad_x, sticky="w")
        self.password_entry = tk.Entry(self.window, font=("Arial", font_size))
        self.password_entry.grid(row=3, column=1, pady=pad_y, padx=pad_x, sticky="ew")

        tk.Label(self.window,
                 text="Роль (1 - Пользователь, 2 - Администратор)",
                 font=("Arial", font_size)).grid(
            row=4, column=0, pady=pad_y, padx=pad_x, sticky="w")
        self.role_entry = tk.Entry(self.window, font=("Arial", font_size))
        self.role_entry.grid(row=4, column=1, pady=pad_y, padx=pad_x, sticky="ew")

        tk.Button(self.window, text="Добавить", command=self.add_user,
                  font=("Arial", font_size)).grid(
            row=5, column=0, columnspan=2,
            pady=pad_y * 2, padx=pad_x, sticky="nsew")

        tk.Button(self.window, text="Назад", command=self.go_back,
                  font=("Arial", font_size)).grid(
            row=6, column=0, columnspan=2,
            pady=pad_y, padx=pad_x, sticky="nsew")

    def add_user(self):
        name = self.name_entry.get()
        surname = self.surname_entry.get()
        login = self.login_entry.get()
        password = self.password_entry.get()
        role = self.role_entry.get()

        if not (name and surname and login and password and role):
            messagebox.showerror("Ошибка", "Заполните все поля")
            return

        execute_query(
            "INSERT INTO POLZOVATELI (Imya, Familiya, Login, Parol, rolid, Parol_smenen) VALUES (%s, %s, %s, %s, %s, FALSE)",
            (name, surname, login, password, role),
            commit=True
        )

        messagebox.showinfo("Успех", "Пользователь добавлен")
        self.window.destroy()

    def go_back(self):
        self.window.destroy()


class ManageUsersWindow:
    """Окно управления пользователями"""

    def __init__(self, parent):
        self.parent = parent
        self.manage_window = tk.Toplevel(parent)
        self.manage_window.title("Управление пользователями")
        self.manage_window.state('zoomed')

        self.main_frame = tk.Frame(self.manage_window)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.table_frame = tk.Frame(self.main_frame)
        self.table_frame.pack(fill=tk.BOTH, expand=True)

        self.bottom_frame = tk.Frame(self.main_frame)
        self.bottom_frame.pack(fill=tk.X, pady=10)

        tk.Button(self.bottom_frame, text="Назад", command=self.go_back,
                  font=("Arial", 14), height=2).pack(fill=tk.X, padx=50, pady=10)

        self.create_user_table()

    def create_user_table(self):
        for widget in self.table_frame.winfo_children():
            widget.destroy()

        self.users = execute_query(
            "SELECT ID, Imya, Familiya, Login, rolid, Zablokirovan FROM POLZOVATELI ORDER BY ID",
            fetchall=True
        )

        self.table_frame.grid_columnconfigure(0, weight=1)
        for i in range(8):
            self.table_frame.grid_columnconfigure(i, weight=1 if i < 7 else 0)

        headers = ["ID", "Имя", "Фамилия", "Логин", "Роль", "Статус", "Действие"]
        for i, text in enumerate(headers):
            tk.Label(self.table_frame, text=text, font=("Arial", 12, "bold"),
                     borderwidth=1, relief="solid").grid(
                row=0, column=i, sticky="nsew", padx=2, pady=2)

        for row_idx, user in enumerate(self.users, start=1):
            user_id, name, surname, login, role, blocked = user
            role_text = "Администратор" if role == 2 else "Пользователь"
            status_text = "Заблокирован" if blocked else "Активен"

            tk.Label(self.table_frame, text=str(user_id), borderwidth=1,
                     relief="solid").grid(row=row_idx, column=0, sticky="nsew", padx=2, pady=2)
            tk.Label(self.table_frame, text=name, borderwidth=1,
                     relief="solid").grid(row=row_idx, column=1, sticky="nsew", padx=2, pady=2)
            tk.Label(self.table_frame, text=surname, borderwidth=1,
                     relief="solid").grid(row=row_idx, column=2, sticky="nsew", padx=2, pady=2)
            tk.Label(self.table_frame, text=login, borderwidth=1,
                     relief="solid").grid(row=row_idx, column=3, sticky="nsew", padx=2, pady=2)
            tk.Label(self.table_frame, text=role_text, borderwidth=1,
                     relief="solid").grid(row=row_idx, column=4, sticky="nsew", padx=2, pady=2)
            tk.Label(self.table_frame, text=status_text, borderwidth=1,
                     relief="solid").grid(row=row_idx, column=5, sticky="nsew", padx=2, pady=2)

            action_frame = tk.Frame(self.table_frame)
            action_frame.grid(row=row_idx, column=6, sticky="nsew", padx=2, pady=2)

            tk.Button(action_frame, text="Редактировать", font=("Arial", 10),
                      command=lambda u_id=user_id: self.edit_user(u_id)).pack(
                side=tk.LEFT, padx=2, fill=tk.X, expand=True)

            if blocked:
                tk.Button(action_frame, text="Разблокировать", font=("Arial", 10),
                          command=lambda u_id=user_id: self.unblock_user(u_id)).pack(
                    side=tk.LEFT, padx=2, fill=tk.X, expand=True)

    def edit_user(self, user_id):
        EditUserWindow(user_id, self.manage_window)

    def unblock_user(self, user_id):
        unblock_user(user_id)
        messagebox.showinfo("Успех", "Пользователь разблокирован")
        self.create_user_table()

    def go_back(self):
        self.manage_window.destroy()


class EditUserWindow:
    """Окно редактирования пользователя"""

    def __init__(self, user_id, parent_window):
        self.edit_window = tk.Toplevel(parent_window)
        self.edit_window.title("Редактирование пользователя")
        self.edit_window.state('zoomed')

        main_container = tk.Frame(self.edit_window)
        main_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)

        form_frame = tk.Frame(main_container)
        form_frame.pack(fill=tk.BOTH, expand=True)

        button_frame = tk.Frame(main_container)
        button_frame.pack(fill=tk.X, pady=(20, 10))

        self.user_id = user_id
        user_data = execute_query(
            "SELECT Imya, Familiya, Login, rolid FROM POLZOVATELI WHERE ID = %s",
            (user_id,), fetchone=True
        )

        if not user_data:
            messagebox.showerror("Ошибка", "Пользователь не найден")
            self.edit_window.destroy()
            return

        name, surname, login, role = user_data

        label_font = ("Arial", 12)
        entry_font = ("Arial", 12)
        button_font = ("Arial", 12, "bold")

        # Сохраняем ключ для роли в переменную для повторного использования
        self.role_key = "Роль (1 - Польз., 2 - Админ.)"
        fields = [
            ("Имя", name),
            ("Фамилия", surname),
            ("Логин", login),
            (self.role_key, str(role))
        ]

        self.entries = {}
        for i, (label, value) in enumerate(fields):
            row_frame = tk.Frame(form_frame)
            row_frame.pack(fill=tk.X, pady=8)

            tk.Label(row_frame, text=label, font=label_font, width=25, anchor="w").pack(side=tk.LEFT)
            entry = tk.Entry(row_frame, font=entry_font)
            entry.insert(0, value)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
            self.entries[label] = entry

        save_btn = tk.Button(button_frame, text="Сохранить изменения",
                             font=button_font, command=self.save_user, height=2)
        save_btn.pack(fill=tk.X, pady=(0, 10))

        back_btn = tk.Button(button_frame, text="Назад",
                             font=button_font, command=self.edit_window.destroy, height=2)
        back_btn.pack(fill=tk.X)

    def save_user(self):
        try:
            data = {key: entry.get() for key, entry in self.entries.items()}

            execute_query(
                "UPDATE POLZOVATELI SET Imya=%s, Familiya=%s, Login=%s, rolid=%s WHERE ID=%s",
                (data["Имя"], data["Фамилия"], data["Логин"],
                 data[self.role_key], self.user_id),
                commit=True
            )

            messagebox.showinfo("Успех", "Данные пользователя обновлены")
            self.edit_window.destroy()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить изменения: {str(e)}")

if __name__ == "__main__":
    HotelApp()