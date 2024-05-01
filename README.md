# Задание.
#### Разработать приложение, реализующее API с токенами авторизации для следующих функций:
1. Авторизация пользователей.
2. Регистрация пользователей.
3. Размещение заметки.
4. Отображение списка заметок с возможностью фильтрации.

API должно быть реализовано в формате REST + JSON.

### Технические требования
- Язык программирования: PHP, Go или Python.
- Допускается использование фреймворков.
- База данных: любая.
- Токен должен передаваться в хедерах запроса.

### Функциональные требования

#### Авторизация пользователя:
- Пользователь должен авторизоваться, отправив логин и пароль в приложение.
- Приложение должно проверить корректность полученных данных и вернуть авторизационный токен в случае успеха.

#### Регистрация пользователей:
- Регистрация должна осуществляться посредством отправки в приложение логина и пароля.
- Необходимо предусмотреть и реализовать разумные ограничения на формат логина и пароля.

#### Размещение заметки:
- Размещение заметки должно происходить посредством отправки данных в формате JSON: заголовок, текст.
- Заметки могут размещать только авторизованные пользователи.
- Необходимо предусмотреть и реализовать разумные ограничения на длину заголовка и текста.
- В успешном ответе вернуть данные добавленной заметки.

#### Редактирование заметки:
- происходит как создание заметки.
- пользователи могут редактировать только свои заметки если срок размещения не больше 1 дня.

#### Отображение списка заметок:
- Лента представляет собой список заметок, отсортированный по дате добавления.
- Реализовать постраничную навигацию и возможность фильтрации по определенным датам или диапазонам добавления, пользователю.
- Для каждой заметки вернуть: заголовок, текст, логин автора.
- Для авторизованных пользователей вернуть признак принадлежности заметки текущему пользователю.

#### Оценка выполнения тестового задания будет осуществляться на основе следующих критериев:
1. Соответствие требованиям задачи.
2. Качество кода, его чистота и структурированность.
3. Эффективность реализации, оптимизация и использование подходящих инструментов.
4. Наличие документации и комментариев к коду.
5. Обработка ошибок и безопасность приложения.

Дополнительные задания (необязательные):
- Добавление удаления заметок.
- Реализация обработки и хранения паролей с использованием хэширования.
- Добавление юнит-тестов.
- Реализация документации к API (например, с помощью Swagger).

**В поле ответа вставь ссылку на открытый гитхаб-репозиторий с кодом решения, ссылку на работающее приложение на публичном хостинге или наличие докера с инструкцией развертывания.**

# Решение.
Был дан список функций, которые необходимо реализовать: 
1. Авторизация пользователей.
2. Регистрация пользователей.
3. Размещение заметки.
4. Отображение списка заметок с возможностью фильтрации.

На данный момент реализованы все перечисленные функции, кроме последней -- отображения списка заметок с возможностью фильтрации. Данный пункт на момент последнего коммита реализован наполовину -- без фильтрации.

### Технические требования

Технические требования выполнены. 
- Проект реализован на языке программирования **Python** с использованием веб-фреймворка FastAPI. 
- В качестве базы данных выбрана Postgresql. 
- Шифрованый токе авторизации передаётся в заголовке запроса *cookie*.

### Функциональные требования

- В части реализации размещения заметок, а также регистрации и авторизации пользователей функциональные требования выполнены в полной мере.
- В части редактирования заметок не реализован функционал, отвечающий за проверку дедлайна для редактирования заметок -- на данный момент можно редактировать заметки любого срока давности.
- При отображении заметок реализовано возвращение необходимых данных пользователю -- отсортированные по дате обновления заголовок, текст, логин автора, а также признак принадлежности заметки текущему пользователю. **Однако пагинация и фильтрация заметок по датам добавления не реализованы.**

### Дополнительные задания

Из части дополнительных заданий, на данный момент реализованы только документация к API (*если я правильно понял, то файл openapi.json и является этой документацией*), а также обработка и хранение паролей с использованием хеширования.
**Добавление  удаления заметок, а также юнит-тесты пока что не реализованы.**

### Инструкция развёртывания

Для того, чтобы развернуть проект на своём локальном компьютере Вам потребуется:

1. Склонировать репозиторий данного проекта: 
```git clone https://github.com/nikitasyan/blog_with_notes.git```
2. В корне проекта создать файл `.env` со следующей структурой:
```
POSTGRES_DIALECT=postgresql
POSTGRES_HOST=<хост БД>
POSTGRES_PORT=<порт БД>
POSTGRES_DB=<имя БД>
POSTGRES_USER=<имя пользователя БД>
POSTGRES_PASSWORD=<пароль пользователя БД>


SECRET_KEY=<набор символов для токена авторизации>
PASSWORD_SALT=<набор символов в качестве соли к паролям>
```
3. Собрать и запустить контейнер командой `docker compose up --build`

По выполнении данных команд, вы сможете зайти в браузер по адресу http://localhost:8001 и увидеть, как проект работает на практике!