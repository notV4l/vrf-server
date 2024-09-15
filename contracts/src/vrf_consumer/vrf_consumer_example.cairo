// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts for Cairo ^0.16.0

#[starknet::contract]
mod VrfConsumer {
    use starknet::{ClassHash, ContractAddress, get_caller_address};
    use starknet::storage::Map;

    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::upgrades::UpgradeableComponent;
    use openzeppelin::upgrades::interface::IUpgradeable;

    use stark_vrf::ecvrf::{Point, Proof, ECVRF, ECVRFImpl};

    use vrf_contracts::vrf_consumer::vrf_consumer_component::{VrfConsumerComponent, RequestStatus};

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: VrfConsumerComponent, storage: vrf_consumer, event: VrfConsumerEvent);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    #[abi(embed_v0)]
    impl VrfConsumerImpl = VrfConsumerComponent::VrfConsumerImpl<ContractState>;

    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;
    impl VrfConsumerInternalImpl = VrfConsumerComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        vrf_consumer: VrfConsumerComponent::Storage,
        scores: Map<ContractAddress, u32>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        VrfConsumerEvent: VrfConsumerComponent::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, vrf_provider: ContractAddress) {
        self.ownable.initializer(owner);
        self.vrf_consumer.initializer(vrf_provider);
    }

    #[derive(Drop, Copy, Clone, Serde)]
    pub struct PredictParams {
        value: bool,
    }

    #[generate_trait]
    impl ConsumerImpl of IConsumer {
        #[abi(embed_v0)]
        // return 0 = executed
        // return seed = committed & random requested
        fn predict(ref self: ContractState, params: PredictParams) -> felt252 {
            // get unique seed
            let seed = self.vrf_consumer.get_unique_seed('predict', params);

            // check not committed or seed = commit
            let commit = self.vrf_consumer.get_commit();
            assert(commit == 0 || commit == seed, 'commit mismatch');

            match self.vrf_consumer.get_status(seed) {
                RequestStatus::None => {
                    self.vrf_consumer.commit(seed);
                    self.vrf_consumer.request_random(seed);
                    seed
                },
                RequestStatus::Received => {
                    panic!("waiting for vrf"); 
                    seed
                },
                RequestStatus::Fulfilled => {
                    // get random
                    let random = self.vrf_consumer.get_random(seed);

                    // do stuff with random
                    self.execute_predict(params, random);

                    // increment nonce
                    self.vrf_consumer.increment_nonce();

                    // clear commit
                    self.vrf_consumer.clear_commit();

                    0
                },
            }
        }
    }

    #[generate_trait]
    impl ConsumerInternal of InternalTrait {
        fn execute_predict(ref self: ContractState, params: PredictParams, random: felt252) {
            let random: u256 = random.into();
            let value = if (random % 2) == 1 {
                true
            } else {
                false
            };

            if params.value == value {
                let caller = get_caller_address();
                let score = self.scores.read(caller);
                self.scores.write(caller, score + 1);
            }
        }
    }
}
