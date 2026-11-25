<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Console\Command;

use Magento\Framework\Console\Cli;
use MageOS\OauthApi\Api\GrantRevokerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Revoke extends Command
{
    private const OPTION_PRINCIPAL = 'principal';
    private const OPTION_CLIENT = 'client';

    public function __construct(
        private readonly GrantRevokerInterface $grantRevoker
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('mageos:oauth:revoke')
            ->setDescription('Revoke OAuth tokens of a principal or a client')
            ->addOption(self::OPTION_PRINCIPAL, null, InputOption::VALUE_REQUIRED, 'Principal, for example admin:5')
            ->addOption(self::OPTION_CLIENT, null, InputOption::VALUE_REQUIRED, 'Client ID');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $principal = $input->getOption(self::OPTION_PRINCIPAL);
        $client = $input->getOption(self::OPTION_CLIENT);
        if (($principal === null) === ($client === null)) {
            $output->writeln('<error>Pass exactly one of --principal or --client.</error>');

            return Cli::RETURN_FAILURE;
        }

        $count = $principal !== null
            ? $this->grantRevoker->revokeForPrincipal((string)$principal)
            : $this->grantRevoker->revokeForClient((string)$client);
        $output->writeln(sprintf('<info>%d tokens revoked.</info>', $count));

        return Cli::RETURN_SUCCESS;
    }
}
