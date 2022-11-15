<?php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Filesystem\Filesystem;

#[AsCommand(name: 'app:download-security-advisories')]
class DownloadCommand extends Command {

    public function __construct(
        // use the %...% syntax for parameters
        #[Autowire('%kernel.project_dir%')]
        protected string $projectDir
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int {
        $filesystem = new Filesystem();
        $filesystem->copy('https://raw.githubusercontent.com/drupal-composer/drupal-security-advisories/9.x/composer.json', $this->projectDir . '/var/repo/composer.json');
        return Command::SUCCESS;
    }

}
