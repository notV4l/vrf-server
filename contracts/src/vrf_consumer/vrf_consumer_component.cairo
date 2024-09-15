use starknet::ContractAddress;
use stark_vrf::ecvrf::{Point, Proof, ECVRF, ECVRFImpl};
use vrf_contracts::vrf_provider::vrf_provider_component::{PublicKey, RequestStatus};


#[starknet::interface]
trait IVrfConsumer<TContractState> {
    fn get_vrf_provider(self: @TContractState) -> ContractAddress;
    fn set_vrf_provider(ref self: TContractState, vrf_provider: ContractAddress);

    fn get_vrf_provider_public_key(self: @TContractState) -> PublicKey;

    fn get_status(self: @TContractState, seed: felt252) -> RequestStatus;
    fn get_random(self: @TContractState, seed: felt252) -> felt252;
}


#[starknet::interface]
trait IVrfConsumerRequest<TContractState> {
    fn request_random(ref self: TContractState, seed: felt252);
}


#[starknet::component]
pub mod VrfConsumerComponent {
    use starknet::{
        ContractAddress, contract_address::ContractAddressZeroable, get_caller_address,
        get_contract_address
    };
    use starknet::storage::Map;

    use openzeppelin::access::ownable::{
        OwnableComponent, OwnableComponent::InternalImpl as OwnableInternalImpl
    };

    use stark_vrf::ecvrf::{Point, Proof, ECVRF, ECVRFImpl};

    use vrf_contracts::vrf_provider::vrf_provider_component::{
        IVrfProvider, IVrfProviderDispatcher, IVrfProviderDispatcherTrait, PublicKey, RequestStatus,
        PublicKeyIntoPoint
    };

    #[storage]
    struct Storage {
        VrfConsumer_vrf_provider: ContractAddress,
        // (contract_address, caller_address) -> nonce
        VrfConsumer_nonces: Map<(ContractAddress, ContractAddress), felt252>,
        // (contract_address, caller_address) -> seed
        VrfConsumer_commit: Map<(ContractAddress, ContractAddress), felt252>,
    }

    #[derive(Drop, starknet::Event)]
    struct VrfProviderChanged {
        address: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    #[event]
    enum Event {
        VrfProviderChanged: VrfProviderChanged,
    }

    pub mod Errors {
        pub const ADDRESS_ZERO: felt252 = 'VrfConsumer: address is zero';
    }

    #[embeddable_as(VrfConsumerImpl)]
    impl VrfConsumer<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        impl Owner: OwnableComponent::HasComponent<TContractState>,
    > of super::IVrfConsumer<ComponentState<TContractState>> {
        fn get_vrf_provider(self: @ComponentState<TContractState>) -> ContractAddress {
            self.VrfConsumer_vrf_provider.read()
        }

        fn set_vrf_provider(
            ref self: ComponentState<TContractState>, vrf_provider: ContractAddress
        ) {
            let mut ownable_component = get_dep_component_mut!(ref self, Owner);
            ownable_component.assert_only_owner();

            self._set_vrf_provider(vrf_provider);
        }

        fn get_vrf_provider_public_key(self: @ComponentState<TContractState>) -> PublicKey {
            IVrfProviderDispatcher { contract_address: self.VrfConsumer_vrf_provider.read() }
                .get_public_key()
        }

        fn get_status(self: @ComponentState<TContractState>, seed: felt252) -> RequestStatus {
            IVrfProviderDispatcher { contract_address: self.VrfConsumer_vrf_provider.read() }
                .get_status(seed)
        }
        fn get_random(self: @ComponentState<TContractState>, seed: felt252) -> felt252 {
            IVrfProviderDispatcher { contract_address: self.VrfConsumer_vrf_provider.read() }
                .get_random(seed)
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {
        fn initializer(ref self: ComponentState<TContractState>, vrf_provider: ContractAddress) {
            self._set_vrf_provider(vrf_provider);
        }

        fn request_random(ref self: ComponentState<TContractState>, seed: felt252,) {
            let vrf_provider = self.VrfConsumer_vrf_provider.read();
            IVrfProviderDispatcher { contract_address: vrf_provider }.request_random(seed);
        }

        fn get_unique_seed<T, +Drop<T>, +Serde<T>>(
            self: @ComponentState<TContractState>, salt: felt252, params: T
        ) -> felt252 {
            let contract = get_contract_address();
            let caller = get_caller_address();
            let nonce = self.VrfConsumer_nonces.read((contract, caller));

            let mut arr: Array<felt252> = array![contract.into(), caller.into(), nonce, salt];
            params.serialize(ref arr);

            core::poseidon::poseidon_hash_span(arr.span())
        }

        fn commit(ref self: ComponentState<TContractState>, seed: felt252) {
            let contract = get_contract_address();
            let caller = get_caller_address();

            self.VrfConsumer_commit.write((contract, caller), seed);
        }

        fn get_commit(ref self: ComponentState<TContractState>) -> felt252 {
            let contract = get_contract_address();
            let caller = get_caller_address();

            self.VrfConsumer_commit.read((contract, caller))
        }

        fn clear_commit(ref self: ComponentState<TContractState>) {
            let contract = get_contract_address();
            let caller = get_caller_address();

            if (self.VrfConsumer_commit.read((contract, caller)) != 0) {
                self.VrfConsumer_commit.write((contract, caller), 0);
            }
        }


        fn increment_nonce(ref self: ComponentState<TContractState>) {
            let contract = get_contract_address();
            let caller = get_caller_address();

            let nonce = self.VrfConsumer_nonces.read((contract, caller));

            self.VrfConsumer_nonces.write((contract, caller), nonce + 1)
        }


        fn _set_vrf_provider(
            ref self: ComponentState<TContractState>, new_vrf_provider: ContractAddress
        ) {
            assert(new_vrf_provider != ContractAddressZeroable::zero(), Errors::ADDRESS_ZERO);
            self.VrfConsumer_vrf_provider.write(new_vrf_provider);

            self.emit(VrfProviderChanged { address: new_vrf_provider })
        }
    }
}
