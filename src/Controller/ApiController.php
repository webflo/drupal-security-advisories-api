<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class ApiController extends AbstractController {

    #[Route('/')]
    public function index(): Response {
        return $this->redirectToRoute('packages-json');
    }

    #[Route('/packages.json', name: 'packages-json')]
    public function packagesJson(): Response {
        $apiUrl = $this->generateUrl('security-advisories-get', [], UrlGeneratorInterface::ABSOLUTE_URL);

        return new JsonResponse([
            'metadata-url' => 'https://packages.drupal.org/files/packages/8/p2/%package%.json',
            'security-advisories' => [
                'metadata' => TRUE,
                'api-url' => $apiUrl,
                'query-all' => TRUE,
            ],
            'available-package-patterns' => [
                "drupal/*",
            ],
        ]);
    }

    #[Route('/api/security-advisories/', name: 'security-advisories-get', methods: ['GET'])]
    public function saGet(Request $request): JsonResponse {
        $packages = $request->query->all('packages');
        if (!is_array($packages)) {
            throw new BadRequestException();
        }
        return $this->handleSa($packages);
    }

    #[Route('/api/security-advisories/', name: 'security-advisories-post', methods: ['POST'])]
    public function saPost(Request $request): JsonResponse {
        $packages = $request->request->all('packages');
        if (!is_array($packages)) {
            throw new BadRequestException();
        }
        return $this->handleSa($packages);
    }

    protected function handleSa(array $packages): JsonResponse {
        $response = [];
        $projectDir = $this->getParameter('kernel.project_dir');
        $composerJson = json_decode(file_get_contents($projectDir . '/var/repo/composer.json'), TRUE);

        $advisories = array_intersect_key($composerJson['conflict'], array_combine($packages, $packages));

        foreach ($advisories as $packageName => $affectedVersions) {
            [$vendor, $project] = explode('/', $packageName);
            $response['advisories'][$packageName] = [
                [
                    'advisoryId' => 'drupal.org--PSA--' . $packageName,
                    'packageName' => $packageName,
                    'affectedVersions' => $affectedVersions,
                    'composerRepository' => 'https://packages.drupal.org/8/',
                    'title' => 'Insecure package: ' . $packageName,
                    'reportedAt' => "2001-01-15 12:00:00",
                    'sources' => [
                        [
                            'name' => 'drupal.org',
                            'remoteId' => $packageName,
                        ],
                    ],
                    'link' => 'http://www.drupal.org/project/' . $project,
                ],
            ];
        }

        return new JsonResponse($response);
    }


}
