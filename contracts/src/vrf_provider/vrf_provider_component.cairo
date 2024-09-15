use starknet::ContractAddress;
use stark_vrf::ecvrf::{Point, Proof, ECVRF, ECVRFImpl};

#[starknet::interface]
trait IVrfProvider<TContractState> {
    fn request_random(ref self: TContractState, seed: felt252);
    fn submit_random(ref self: TContractState, seed: felt252, proof: Proof);

    fn get_status(self: @TContractState, seed: felt252) -> RequestStatus;
    fn get_random(self: @TContractState, seed: felt252) -> felt252;

    fn get_public_key(self: @TContractState) -> PublicKey;
    fn set_public_key(ref self: TContractState, new_pubkey: PublicKey);
}

//
//
//

#[derive(Drop, Copy, Clone, Serde, PartialEq, starknet::Store)]
pub enum RequestStatus {
    None,
    Received,
    Fulfilled,
}


#[derive(Drop, Copy, Clone, Serde, starknet::Store)]
pub struct PublicKey {
    x: felt252,
    y: felt252,
}

impl PublicKeyIntoPoint of Into<PublicKey, Point> {
    fn into(self: PublicKey) -> Point {
        Point { x: self.x, y: self.y }
    }
}

//
//
//

#[starknet::component]
pub mod VrfProviderComponent {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::Map;

    use openzeppelin::access::ownable::{
        OwnableComponent, OwnableComponent::InternalImpl as OwnableInternalImpl
    };

    use super::{RequestStatus, PublicKey};

    use stark_vrf::ecvrf::{Point, Proof, ECVRF, ECVRFImpl};

    #[storage]
    struct Storage {
        VrfProvider_pubkey: PublicKey,
        // seed -> random
        VrfProvider_request_random: Map<felt252, felt252>,
        // seed -> status
        VrfProvider_request_status: Map<felt252, RequestStatus>,
    }

    #[derive(Drop, starknet::Event)]
    struct PublicKeyChanged {
        pubkey: PublicKey,
    }

    #[derive(Drop, starknet::Event)]
    struct RequestRandom {
        caller: ContractAddress,
        seed: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct SubmitRandom {
        seed: felt252,
        proof: Proof,
    }

    #[derive(Drop, starknet::Event)]
    #[event]
    enum Event {
        PublicKeyChanged: PublicKeyChanged,
        RequestRandom: RequestRandom,
        SubmitRandom: SubmitRandom,
    }

    pub mod Errors {
        pub const PUBKEY_ZERO: felt252 = 'VrfProvider: pubkey is zero';
        pub const ALREADY_FULFILLED: felt252 = 'VrfProvider: already fulfilled';
    }

    #[embeddable_as(VrfProviderImpl)]
    impl VrfProvider<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        impl Owner: OwnableComponent::HasComponent<TContractState>,
    > of super::IVrfProvider<ComponentState<TContractState>> {
        fn request_random(ref self: ComponentState<TContractState>, seed: felt252,) {
            let status = self.VrfProvider_request_status.read(seed);
            if status == RequestStatus::None {
                let caller = get_caller_address();
                self.VrfProvider_request_status.write(seed, RequestStatus::Received);
                self.emit(RequestRandom { caller, seed, });
            }
        }

        fn submit_random(ref self: ComponentState<TContractState>, seed: felt252, proof: Proof) {
            // TODO: check allowed ?
            // self.accesscontrol.assert_only_executor();

            // check status
            let curr_status = self.VrfProvider_request_status.read(seed);
            assert(curr_status != RequestStatus::Fulfilled, Errors::ALREADY_FULFILLED);

            // verify proof
            let pubkey: Point = self.get_public_key().into();
            let ecvrf = ECVRFImpl::new(pubkey);

            let hash = ecvrf.verify(proof.clone(), array![seed.clone()].span()).unwrap();

            // write rand
            self.VrfProvider_request_random.write(seed, hash);
            // update request status
            self.VrfProvider_request_status.write(seed, RequestStatus::Fulfilled);

            self.emit(SubmitRandom { seed, proof });
        }

        fn get_status(self: @ComponentState<TContractState>, seed: felt252) -> RequestStatus {
            self.VrfProvider_request_status.read(seed)
        }

        fn get_random(self: @ComponentState<TContractState>, seed: felt252) -> felt252 {
            self.VrfProvider_request_random.read(seed)
        }

        fn get_public_key(self: @ComponentState<TContractState>) -> PublicKey {
            self.VrfProvider_pubkey.read()
        }

        fn set_public_key(ref self: ComponentState<TContractState>, new_pubkey: PublicKey) {
            let mut ownable_component = get_dep_component_mut!(ref self, Owner);
            ownable_component.assert_only_owner();

            self._set_public_key(new_pubkey);
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {
        fn initializer(ref self: ComponentState<TContractState>, pubkey: PublicKey) {
            self._set_public_key(pubkey);
        }

        fn _set_public_key(ref self: ComponentState<TContractState>, new_pubkey: PublicKey) {
            assert(new_pubkey.x != 0 && new_pubkey.y != 0, Errors::PUBKEY_ZERO);
            self.VrfProvider_pubkey.write(new_pubkey);

            self.emit(PublicKeyChanged { pubkey: new_pubkey })
        }
    }
}
