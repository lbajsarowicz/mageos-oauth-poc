<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Console\Command;

use Defuse\Crypto\Key;
use Magento\Framework\App\DeploymentConfig\Writer;
use Magento\Framework\Config\File\ConfigFilePool;
use Magento\Framework\Console\Cli;
use MageOS\Oauth\Model\Config;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Writes the RSA signing key pair and the encryption key to env.php. Rotating them invalidates every issued token.
 */
class GenerateKeys extends Command
{
    private const OPTION_FORCE = 'force';

    public function __construct(
        private readonly Config $config,
        private readonly Writer $writer
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('mageos:oauth:keys:generate')
            ->setDescription('Generate the OAuth signing and encryption keys in env.php')
            ->addOption(self::OPTION_FORCE, null, InputOption::VALUE_NONE, 'Replace existing keys');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if ($this->config->hasKeys() && !$input->getOption(self::OPTION_FORCE)) {
            $output->writeln(
                '<error>Keys exist. Use --force to rotate them; every issued token stops working.</error>'
            );

            return Cli::RETURN_FAILURE;
        }

        $privateKey = openssl_pkey_new(['private_key_bits' => 3072, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($privateKey === false || !openssl_pkey_export($privateKey, $privatePem)) {
            $output->writeln('<error>OpenSSL could not generate an RSA key.</error>');

            return Cli::RETURN_FAILURE;
        }
        $publicPem = openssl_pkey_get_details($privateKey)['key'];

        $this->writer->saveConfig([
            ConfigFilePool::APP_ENV => [
                'mageos_oauth' => [
                    'private_key' => $privatePem,
                    'public_key' => $publicPem,
                    'encryption_key' => Key::createNewRandomKey()->saveToAsciiSafeString(),
                ],
            ],
        ], true);
        $output->writeln('<info>OAuth keys written to app/etc/env.php.</info>');

        return Cli::RETURN_SUCCESS;
    }
}
