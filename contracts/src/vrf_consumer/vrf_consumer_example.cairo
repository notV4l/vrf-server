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
        // fn request_random(
        //     ref self: ComponentState<TContractState>,
        //     consumer: ContractAddress,
        //     entrypoint: felt252,
        //     calldata: Array<felt252>,
        //     nonce: felt252
        // ) 

        #[abi(embed_v0)]
        fn predict(ref self: ContractState, params: PredictParams) {
            // check if call match with commit
            let seed = self.vrf_consumer.assert_call_match_commit('predict', params);
            // retrieve random & clear commit
            let random = self.vrf_consumer.assert_fulfilled_and_consume(seed);

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

    #[generate_trait]
    impl ConsumerInternal of InternalTrait {}
}
