package ledger_filecoin_go

import "fmt"

func isCryptoCurveSupported(curve CryptoCurve) error {
	switch curve {
	case SECP256K1:
		return nil
	default:
		return fmt.Errorf("curve not supported yet")

	}
}
