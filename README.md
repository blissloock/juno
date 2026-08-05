# 🚀 Proyecto Juno (Backend)

Bienvenido al repositorio del backend de **Proyecto Juno**. Este sistema está construido con Rust (Actix-Web) y utiliza contenedores Docker para orquestar la API, una base de datos de series temporales (TimescaleDB) y un servidor web ligero (Nginx) para el frontend.

## 📋 Requisitos Previos

Para ejecutar este proyecto en tu máquina local, necesitas tener instalado:
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) (o Docker Engine).
* Git.

## 🛠️ Instrucciones de Instalación

**1. Clonar el repositorio**
Descarga el código a tu computadora ejecutando:
`git clone https://github.com/blissloock/juno`

**2. Configurar las Variables de Entorno**
Por seguridad, las contraseñas no se suben a GitHub. Crea un archivo llamado exactamente `.env` en la carpeta raíz del proyecto y solicita las credenciales al administrador del equipo para llenarlo. 

El archivo debe tener exactamente esta estructura:
```env
POSTGRES_DB=juno
POSTGRES_USER=postgres
POSTGRES_PASSWORD=tu_password_seguro
GMAIL_USER=tu_correo@gmail.com
GMAIL_PASS=tu_contraseña_de_aplicacion
JWT_SECRET=tu_secreto_super_seguro
FRONTEND_ORIGIN=http://localhost
```

**3. Levantar la Infraestructura**
Una vez creado el archivo `.env`, abre tu terminal en la raíz del proyecto y ejecuta el siguiente comando para compilar el código y levantar los contenedores:
`docker compose -f docker-compose.yml up --build -d`

**4. Verificar los Servicios**
Si todo salió bien, los servicios estarán disponibles en las siguientes direcciones:
* **Frontend (Nginx):** http://localhost
* **Backend API (Rust):** http://localhost:8080
* **Puerto NetFlow:** 2055 (UDP)

## 🛑 Detener el Proyecto

Para apagar los contenedores sin borrar los datos de tu base de datos, ejecuta:
`docker compose -f docker-compose.yml down`
