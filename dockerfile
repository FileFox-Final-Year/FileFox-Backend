# -------- BUILD STAGE --------
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY FileFox-Backend.sln ./
COPY FileFox_Backend/*.csproj ./FileFox_Backend/
COPY FileFox_Backend.Tests/*.csproj ./FileFox_Backend.Tests/

RUN dotnet restore FileFox-Backend.sln

COPY . .

RUN dotnet publish FileFox-Backend.sln -c Release -o /app/publish

# -------- RUNTIME STAGE --------
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080

COPY --from=build /app/publish .

EXPOSE 8080

ENTRYPOINT ["dotnet", "FileFox-Backend.dll"]