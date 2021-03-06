# Установка

- [Установка](#installation)
    - [Параметры сервера](#server-requirements)
    - [Установка Laravel](#installing-laravel)
    - [Конфигурация](#configuration)

<a name="installation"></a>
## Установка

<a name="server-requirements"></a>
### Параметры сервера

Фреймворк Laravel может работать с виртуальной машиной [Laravel Homestead](/docs/{{version}}/homestead) "из коробки", так что для разработки рекомендуется использовать именно ее.

Однако, если Вы не используете Homestead, убедитесь, что Ваш сервер отвечает следующим требованиям:

<div class="content-list" markdown="1">
- PHP >= 5.5.9
- OpenSSL PHP Extension
- PDO PHP Extension
- Mbstring PHP Extension
- Tokenizer PHP Extension
</div>

<a name="installing-laravel"></a>
### Установка Laravel

Для управления зависимостями, Laravel использует менеджер зависимостей [Composer](http://getcomposer.org). Перед началом установки фреймворка убедитесь, что он установлен на Вашем компьютере.

#### С помощью Laravel Installer

Вначале скачайте установщик Laravel, используя [Composer](http://getcomposer.org):

    composer global require "laravel/installer"

Укажите директорию `~/.composer/vendor/bin` (или эквивалентную в Вашей ОС) в глобальной переменной `PATH` для того, чтобы ОС могла использовать команду `laravel`.

После установки, команда `laravel new` создаст "чистый" проект в директории, которую Вы укажете третьим параметром. Например, выполнив команду `laravel new blog`, установщик создаст папку `blog` и разместит в ней "чистый" исходник фреймворка с уже всеми установленными зависимостями. Этот метод намного быстрее, нежели установка через [Composer](http://getcomposer.org).

    laravel new blog

#### С помощью Composer

В качестве альтернативы, Вы можете установить фреймворк Laravel используя команду Композера `create-project` в командной строке:

    composer create-project --prefer-dist laravel/laravel blog

Как и в примере выше, команда создаст папку `blog` с размещенным внутри готовым фреймворком.

<a name="configuration"></a>
### Конфигурация

Все файлы конфигурации фреймворка Laravel хранятся в папке `config`. Каждая опция документирована, так что не стесняйтесь просматривать файлы и искать доступные варианты настроек.

#### Права доступа

После установки Laravel, возможно, потребуется настроить некоторые разрешения. Папки `storage` и `bootstrap/cache` должны иметь права на запись от сервера, иначе фреймворк не будет работать. Если Вы используете виртуальную машину [Homestead](/docs/{{version}}/homestead), все необходимые права доступа будут назначены автоматически.

#### Ключ приложения

Следующее, что Вы должны сделать после установки Laravel - это присвоить случайный ключ Вашему приложению. Если Вы установили фреймворк с помощью композера или Laravel Installer, этот ключ будет установлен при выполнении команды `php artisan key:generate`. Как правило, строка ключа должна быть длиной не более 32 символов. Ключ должен быть указан в файле `.env` в корне директории. Если Вы еще не переименовали файл `.env.example` в `.env`, то должны сделать это сейчас (обычно, установщик Laravel и Composer автоматически переименовывают данный файл). ** Если ключ приложения не будет установлен, приложение не сможет защитить Ваши пользовательские сессии при передаче данных, например, пароля при авторизации.**


#### Дополнительные настройки

Laravel практически не требует изменения конфигурации "из коробки". Вы уже можете начать разработку! Тем не менее, Вы можете посмотреть файл `config/app.php` и его документацию. Он содержит несколько опций, таких как `timezone` и `locale`, которые можете изменить на Ваше усмотрение.

Также Вы можете настроить несколько дополнительных компонентов Laravel, таких как:

- [Кэш](/docs/{{version}}/cache#configuration)
- [База данных](/docs/{{version}}/database#configuration)
- [Сессии](/docs/{{version}}/session#configuration)

После установки Laravel, Вы должны [настроить локальную среду](/docs/{{version}}/configuration#environment-configuration).
