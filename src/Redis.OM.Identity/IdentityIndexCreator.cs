using Redis.OM.Identity.Models;

namespace Redis.OM.Identity
{
    public class IdentityIndexCreator //: IHostedService
    {
        private readonly RedisConnectionProvider _provider;
        public IdentityIndexCreator(RedisConnectionProvider provider)
        {
            _provider = provider;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await DropAllIndexs();

            await _provider.Connection.CreateIndexAsync(typeof(IdentityRole));
            await _provider.Connection.CreateIndexAsync(typeof(IdentityRoleClaim));
            await _provider.Connection.CreateIndexAsync(typeof(IdentityUser));
            await _provider.Connection.CreateIndexAsync(typeof(IdentityUserClaim));
            await _provider.Connection.CreateIndexAsync(typeof(IdentityUserLogin));
            await _provider.Connection.CreateIndexAsync(typeof(IdentityUserRole));
            await _provider.Connection.CreateIndexAsync(typeof(IdentityUserToken));

        }
        private async Task DropAllIndexs()
        {

            await _provider.Connection.DropIndexAsync(typeof(IdentityRole));
            await _provider.Connection.DropIndexAsync(typeof(IdentityRoleClaim));
            await _provider.Connection.DropIndexAsync(typeof(IdentityUser));
            await _provider.Connection.DropIndexAsync(typeof(IdentityUserClaim));
            await _provider.Connection.DropIndexAsync(typeof(IdentityUserLogin));
            await _provider.Connection.DropIndexAsync(typeof(IdentityUserRole));
            await _provider.Connection.DropIndexAsync(typeof(IdentityUserToken));
        }


        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }


    }
}
