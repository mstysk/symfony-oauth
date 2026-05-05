<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20260429203041 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE oauth_access_tokens (identifier VARCHAR(191) NOT NULL, client_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) DEFAULT NULL, expires_at DATETIME NOT NULL, scopes CLOB NOT NULL, audience CLOB NOT NULL, revoked BOOLEAN NOT NULL, PRIMARY KEY (identifier))');
        $this->addSql('CREATE TABLE oauth_auth_codes (identifier VARCHAR(191) NOT NULL, client_id VARCHAR(191) NOT NULL, user_id VARCHAR(191) DEFAULT NULL, expiry_date_time DATETIME NOT NULL, scope_ids CLOB NOT NULL, redirect_uri VARCHAR(2048) DEFAULT NULL, code_challenge VARCHAR(255) DEFAULT NULL, code_challenge_method VARCHAR(16) DEFAULT NULL, resource VARCHAR(2048) DEFAULT NULL, revoked BOOLEAN NOT NULL, PRIMARY KEY (identifier))');
        $this->addSql('CREATE TABLE oauth_clients (id BLOB NOT NULL, client_identifier VARCHAR(191) NOT NULL, client_name VARCHAR(191) NOT NULL, secret_hash VARCHAR(255) DEFAULT NULL, confidential BOOLEAN NOT NULL, redirect_uris CLOB NOT NULL, grant_types CLOB NOT NULL, scopes_allowed CLOB NOT NULL, dcr_metadata CLOB NOT NULL, created_at DATETIME NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_13CE8101E77ABE2B ON oauth_clients (client_identifier)');
        $this->addSql('CREATE TABLE oauth_refresh_tokens (identifier VARCHAR(191) NOT NULL, access_token_id VARCHAR(191) NOT NULL, family_id BLOB NOT NULL, expires_at DATETIME NOT NULL, revoked BOOLEAN NOT NULL, PRIMARY KEY (identifier))');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('DROP TABLE oauth_access_tokens');
        $this->addSql('DROP TABLE oauth_auth_codes');
        $this->addSql('DROP TABLE oauth_clients');
        $this->addSql('DROP TABLE oauth_refresh_tokens');
    }
}
