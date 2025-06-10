# Вариант 1: Используем стабильную версию .NET 8.0
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Копируем исходники
COPY . ./

# Восстанавливаем зависимости
RUN dotnet restore DemoAuth.csproj

# Публикуем проект
RUN dotnet publish DemoAuth.csproj -c Release -o out --no-restore

# Используем runtime образ
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/out .

# Открываем порт
EXPOSE 5205

# Устанавливаем переменные окружения
ENV ASPNETCORE_URLS=http://+:5205
ENV ASPNETCORE_ENVIRONMENT=Production

# Запуск
ENTRYPOINT ["dotnet", "DemoAuth.dll"]