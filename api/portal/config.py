from pydantic_settings import BaseSettings

class PortalSettings(BaseSettings):
    SECRET_KEY: str
    ADMIN_EMAIL: str = "admin-dify@admin.net"

portal_settings = PortalSettings()