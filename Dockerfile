FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY GJNET.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish GJNET.csproj -c Release -o /out --no-restore
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /out .
ENV ASPNETCORE_HTTP_PORTS=8080 DataPath=/data
USER root
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/* && mkdir /data && chown $APP_UID:$APP_UID /data
USER $APP_UID
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD ["dotnet", "GJNET.dll", "--healthcheck"]
ENTRYPOINT ["dotnet", "GJNET.dll"]
