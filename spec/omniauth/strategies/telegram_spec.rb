require 'spec_helper'

RSpec.describe OmniAuth::Strategies::Telegram do
  let(:app) { lambda { |env| [200, {}, ["Hello World."]] } }
  let(:button_config) { nil }
  let(:settings) { nil }
  let(:bot_name) { 'BOT_NAME' }
  let(:secret) { 'BOT_SECRET' }
  let(:request) { double(:request, params: params) }
  let(:env) { {} }
  let(:params) { {} }

  subject(:strategy) do
    config = { bot_name: bot_name, secret: secret }
    config[:button_config] = button_config if button_config
    config[:settings] = settings if settings
    described_class.new(app, config)
  end


  before do
    allow(strategy).to receive(:request) { request }
    allow(strategy).to receive(:env) { env }
  end

  describe 'default options' do
    it 'has correct name' do
      expect(subject.options.name).to eq('telegram')
    end

    it 'has correct settings' do
      expect(subject.options.settings).to eq({})
    end

    it 'has correct bot name' do
      expect(subject.options.bot_name).to eq('BOT_NAME')
    end

    it 'has correct secret' do
      expect(subject.options.secret).to eq('BOT_SECRET')
    end

    it 'has correct button config' do
      expect(subject.options.button_config).to eq({})
    end
  end

  describe '#request_phase' do
    let(:method_result) { strategy.request_phase }
    let(:status) { method_result[0] }
    let(:headers) { method_result[1] }
    let(:body) { method_result[2].body.first }

    before do
      allow(strategy).to receive(:callback_url) { 'CALLBACK_URL' }
    end

    it 'has correct rack response status' do
      expect(status).to eq(200)
    end

    it 'has correct headers' do
      expect(headers).to include('content-type' => 'text/html')
      expect(headers).to include('Content-Length')
    end

    context 'when settings is blank' do
      it 'has correct body' do
        expect(body).to include('CALLBACK_URL')
        expect(body).to include('src="https://telegram.org/js/telegram-widget.js?5"')
        expect(body).to include('Telegram Login')
        expect(body).not_to include('data-request-access')
        expect(body).to include('data-telegram-login="BOT_NAME"')
      end
    end

    context 'when settings is not blank' do
      let(:settings) { { button_script_url: 'BUTTON_SCRIPT_URL', request_access: true, request_phase_title: 'TITLE' } }

      it 'has correct body' do
        expect(body).to include('CALLBACK_URL')
        expect(body).to include('src="BUTTON_SCRIPT_URL"')
        expect(body).to include('TITLE')
        expect(body).to include('data-telegram-login="BOT_NAME"')
        expect(body).to include('data-request-access="write"')
      end
    end

    context 'when button_config is not blank' do
      let(:button_config) { { other_arg: 'OTHER_ARG_VALUE', radius: 'RADIUS_VALUE' } }

      it 'has correct body' do
        expect(body).to include('data-radius="RADIUS_VALUE"')
        expect(body).to include('data-other-arg="OTHER_ARG_VALUE"')
      end
    end

    context 'when bot name is other' do
      let(:bot_name) { 'otherbotname' }

      it 'has correct body' do
        expect(body).to include('data-telegram-login="otherbotname"')
      end
    end
  end

  describe '#callback_phase' do
    subject(:method_result) { strategy.callback_phase }
    let(:status) { method_result[0] }
    let(:headers) { method_result[1] }
    let(:body) { method_result[2].body.first }

    def failure_path(key)
      "/auth/failure?message=#{key}&strategy=telegram"
    end

    context 'when params are blank' do
      let(:params) { {} }

      it { expect(status).to eq(302) }
      it { expect(headers).to include('Location' => failure_path(:missing_required_field)) }
    end

    context 'when params are has not all required params' do
      let(:params) { { 'id' => '1', 'first_name' => 'Joe', 'last_name' => 'Smith', 'hash' => 'HASH' } }

      it { expect(status).to eq(302) }
      it { expect(headers).to include('Location' => failure_path(:missing_required_field)) }
    end

    context 'when params are has all required params' do
      let(:params) do
        { 'id' => '1', 'first_name' => 'Joe', 'last_name' => 'Smith',
          'hash' => hash, 'auth_date' => auth_date.to_i.to_s }
      end
      let(:auth_date) { Time.at(123) }
      let(:hash) { 'HASH' }

      it { expect(headers).not_to include('Location' => failure_path(:missing_required_field)) }

      context 'when params signature is invalid' do
        it { expect(status).to eq(302) }
        it { expect(headers).to include('Location' => failure_path(:signature_mismatch)) }
      end

      context 'when params signature is valid' do
        let(:hash) { '329836bbd274845eb708f60f97c9029229dfc4a99215454013fcc5f49cf62cd5' }

        it { expect(status).to eq(302) }
        it { expect(headers).not_to include('Location' => failure_path(:signature_mismatch)) }

        context 'when params has optional keys' do
          let(:params) do
            super().merge('photo_url' => 'PHOTO_URL', 'username' => 'joe.smith', 'new_telegram_key' => 'NEW KEY VALUE')
          end
          let(:hash) { 'bc9c7ce596f8611af871975c070d41bfa487ecabcaacdf4a80b730e71e9790ee' }

          it { expect(status).to eq(302) }
          it { expect(headers).not_to include('Location' => failure_path(:signature_mismatch)) }
        end
      end

      context 'when signature is valud' do
        before do
          expect(strategy).to receive(:valid_signature?) { true }
        end

        context 'when auth_date is invalid' do
          it { expect(status).to eq(302) }
          it { expect(headers).to include('Location' => failure_path(:session_expired)) }
        end

        context 'when auth_date is valid' do
          let(:auth_date) { Time.now - 12 * 3600 }

          it { expect(status).to eq(200) }
          it { expect(headers).not_to include('Location' => failure_path(:session_expired)) }
        end

        context 'when settings has auth_date_limit' do
          let(:auth_date) { Time.now - 12 * 3600 }
          let(:settings) { { 'auth_date_limit' => 10 * 3600 } }

          it { expect(status).to eq(302) }
          it { expect(headers).to include('Location' => failure_path(:session_expired)) }
        end
      end
    end
  end

  describe '#extra' do
    subject { strategy.extra }
    let(:params) do
      { 'id' => '1', 'first_name' => 'Joe', 'last_name' => 'Smith',
        'hash' => hash, 'auth_date' => Time.new(2000, 1, 2, 12, 30).to_i.to_s }
    end

    it 'includes data from params' do
      is_expected.to eq(auth_date: Time.new(2000, 1, 2, 12, 30))
    end
  end

  describe '#uid' do
    subject { strategy.uid }
    let(:params) do
      { 'id' => 'ID_VALUE', 'first_name' => 'Joe', 'last_name' => 'Smith',
        'hash' => hash, 'auth_date' => '123' }
    end

    it 'includes data from params' do
      is_expected.to eq('ID_VALUE')
    end
  end

  describe '#info' do
    subject { strategy.info }
    let(:params) do
      { 'id' => 'ID_VALUE', 'first_name' => 'Joe', 'last_name' => 'Smith', 'photo_url' => 'PHOTO_URL',
        'hash' => hash, 'auth_date' => '123', 'username' => 'joe.smith' }
    end

    it 'includes data from params' do
      is_expected.to eq(name: 'Joe Smith', nickname: 'joe.smith',
                        first_name: 'Joe', last_name: 'Smith', image: 'PHOTO_URL')
    end
  end
end
