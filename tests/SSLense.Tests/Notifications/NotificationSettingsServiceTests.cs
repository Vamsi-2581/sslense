using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Notifications;

public sealed class NotificationSettingsServiceTests
{
    [Fact]
    public async Task SetEmailAsync_RelayWithoutSignIn_SavesWithoutAnyPassword()
    {
        var (service, saved) = CreateService();

        await service.SetEmailAsync(new EmailSettingsRequest(
            "contoso-com.mail.protection.outlook.com", 25, SmtpSecurity.StartTls, SmtpAuthentication.None,
            null, null, "alerts@contoso.com", ["ops@contoso.com", " admin@contoso.com "]));

        var email = saved().Notifications.Email!;
        Assert.Equal(SmtpAuthentication.None, email.Authentication);
        Assert.Null(email.ProtectedPassword);
        Assert.Null(email.Username);
        Assert.Equal(["ops@contoso.com", "admin@contoso.com"], email.To);
    }

    [Fact]
    public async Task SetEmailAsync_Password_IsProtectedAndKeptWhenNotReentered()
    {
        var (service, saved) = CreateService();
        await service.SetEmailAsync(new EmailSettingsRequest(
            "smtp.example.com", 587, SmtpSecurity.StartTls, SmtpAuthentication.Password,
            "user", "super-secret", "from@example.com", ["to@example.com"]));
        var protectedPassword = saved().Notifications.Email!.ProtectedPassword;

        await service.SetEmailAsync(new EmailSettingsRequest(
            "smtp.example.com", 587, SmtpSecurity.StartTls, SmtpAuthentication.Password,
            "user", null, "from@example.com", ["other@example.com"]));

        Assert.DoesNotContain("super-secret", protectedPassword, StringComparison.Ordinal);
        Assert.Equal(protectedPassword, saved().Notifications.Email!.ProtectedPassword);
    }

    [Theory]
    [InlineData(SmtpSecurity.None, "user", "secret", "unencrypted")]
    [InlineData(SmtpSecurity.StartTls, "new-user", null, "Enter the SMTP password")]
    public async Task SetEmailAsync_UnsafeOrIncomplete_IsRefused(SmtpSecurity security, string user, string? password, string expected)
    {
        var (service, _) = CreateService(new NotificationConfig
        {
            Email = new EmailNotificationConfig("smtp.example.com", 587, SmtpSecurity.StartTls, SmtpAuthentication.Password,
                "user", "cHJvdGVjdGVk", "from@example.com", ["to@example.com"])
        });

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => service.SetEmailAsync(new EmailSettingsRequest(
            "smtp.example.com", 587, security, SmtpAuthentication.Password, user, password, "from@example.com", ["to@example.com"])));

        Assert.Contains(expected, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AddAndRemoveChat_ProtectsUrlsAndShowsOnlyTheHost()
    {
        var (service, saved) = CreateService();

        await service.AddChatAsync(new ChatSettingsRequest(ChatFormat.Teams, "https://prod.westus.logic.azure.com/workflows/abc?sig=SECRET", "ops"));
        await service.AddChatAsync(new ChatSettingsRequest(ChatFormat.Ntfy, "https://ntfy.sh/sslense-alerts"));
        var overview = await service.GetOverviewAsync();
        await service.RemoveChatAsync(1);

        Assert.DoesNotContain(overview.Chat, chat => chat.Host.Contains("SECRET", StringComparison.Ordinal));
        Assert.Equal("prod.westus.logic.azure.com", overview.Chat[0].Host);
        Assert.Equal(ChatFormat.Ntfy, Assert.Single(saved().Notifications.Chat).Format);
    }

    [Theory]
    [InlineData(ChatFormat.Teams, "http://teams.example.com/hook", "https://")]
    [InlineData(ChatFormat.Telegram, "https://api.telegram.org/bot123:abc/sendMessage", "chat_id")]
    [InlineData(ChatFormat.Ntfy, "https://ntfy.sh/", "topic")]
    public async Task AddChatAsync_InvalidUrl_IsRefusedWithGuidance(ChatFormat format, string url, string expected)
    {
        var (service, _) = CreateService();

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => service.AddChatAsync(new ChatSettingsRequest(format, url)));

        Assert.Contains(expected, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ClearAsync_RemovesChannelsButKeepsTheEventLogOn()
    {
        var (service, saved) = CreateService(new NotificationConfig
        {
            EventLogEnabled = false,
            Chat = [new ChatNotificationConfig(ChatFormat.Slack, "eA==")]
        });

        await service.ClearAsync();

        Assert.Empty(saved().Notifications.Chat);
        Assert.True(saved().Notifications.EventLogEnabled);
    }

    private static (NotificationSettingsService Service, Func<AppConfig> Saved) CreateService(NotificationConfig? initial = null)
    {
        var current = new AppConfig { Notifications = initial ?? new NotificationConfig() };
        var configStore = new Mock<IConfigStore>(MockBehavior.Strict);
        configStore.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => current);
        configStore.Setup(value => value.SaveAsync(It.IsAny<AppConfig>(), It.IsAny<CancellationToken>()))
            .Callback<AppConfig, CancellationToken>((config, _) => current = config)
            .Returns(Task.CompletedTask);

        // Reversible stand-in for DPAPI: prefixes the plaintext, so "protected" values never equal the input.
        var protector = new Mock<ISecretProtector>(MockBehavior.Strict);
        protector.Setup(value => value.Protect(It.IsAny<byte[]>()))
            .Returns<byte[]>(plaintext => Encoding.UTF8.GetBytes($"protected:{Encoding.UTF8.GetString(plaintext)}"));
        protector.Setup(value => value.Unprotect(It.IsAny<byte[]>()))
            .Returns<byte[]>(data => Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(data).Replace("protected:", string.Empty)));
        return (new NotificationSettingsService(configStore.Object, protector.Object), () => current);
    }
}
