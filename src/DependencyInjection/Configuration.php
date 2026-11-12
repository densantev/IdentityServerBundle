<?php

namespace Denux\IdentityServerBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('identity_server');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
                ->scalarNode('issuer')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('audience')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('jwks_uri')->isRequired()->cannotBeEmpty()->end()
                ->integerNode('jwks_cache_ttl')->defaultValue(300)->min(1)->end()
                ->integerNode('clock_skew')->defaultValue(30)->min(0)->end()
            ->end();

        return $treeBuilder;
    }
}
