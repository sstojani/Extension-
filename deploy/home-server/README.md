# soc-watch: home server deployment

Portainer Source: this repository. Branch: master.
Compose path: `compose.home-server.yaml`. Stack name: `soc-watch`.
Polling: 5m. `pull_policy: build` rebuilds source changes.

Existing state and secrets stay under `/home/semi/app-deploy`; they are never committed.
The shared Docker network must already exist: `nginx-learning_default`.
Stop the old `home-apps` service before the first Portainer deployment. Never run two writers on the same state folder.
Startup first creates a SQLite-consistent private state backup under `/home/semi/app-deploy/backups/gitops/soc-watch`. A failed backup prevents startup. Backups are local and retained until deliberately removed; copy them off-server as well.
Docker health checks report runtime health. Portainer polling is deployment automation, not a full CI test runner or automatic database rollback.
The image build runs SOC Watch tests, type checking and the web/extension builds.
Revert a bad Git commit to trigger a fresh build. For database schema changes, restore a compatible backup with the app stopped; never blindly restore old data over new writes.
Changing provider integrations in the app settings normally needs no Docker or NPM change.
