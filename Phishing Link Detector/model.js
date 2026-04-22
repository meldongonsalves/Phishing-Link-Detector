// model.js
// Logistic Regression classifier for phishing URL detection.
// Weights trained by train_model.py on phishing URL dataset.
//
// Training results:
//   Accuracy:           99.32%
//   Precision:          100.00%
//   Recall:             98.64%
//   F1 Score:           99.31%
//   AUC-ROC:            100.00%
//   False Positive Rate:0.00%
//   Training set:       1760 URLs
//   Test set:           440 URLs
//   Cross-val accuracy: 99.66% (+/- 0.21%)

const MODEL_WEIGHTS = {
  bias:                   -13.4429,   // trained intercept

  // URL structure features
  urlLength:              0.0310,
  numDots:                0.6611,
  numHyphens:             0.5217,
  hasHttps:               -1.6861,
  domainLength:           0.1308,

  // Strong phishing signals
  hasIpAddress:           1.4137,
  hasAtSymbol:            2.7383,
  brandInSubdomain:       2.2931,
  isTyposquat:            2.5502,

  // Keyword and pattern signals
  suspiciousKeywordCount: 0.9895,
  numSubdomains:          1.0437,
  hasEncoding:            1.3466,
  hasDigitsInDomain:      1.4703,
  hasSuspiciousTld:       3.0690,
  scamKeywordCount:       0.8916,
  isLongCompoundDomain:   1.7483,
};

function sigmoid(z) {
  return 1 / (1 + Math.exp(-z));
}

function computePhishingProbability(features) {
  if (!features) return 0;

  let z = MODEL_WEIGHTS.bias;
  z += (features.urlLength              || 0) * MODEL_WEIGHTS.urlLength;
  z += (features.numDots                || 0) * MODEL_WEIGHTS.numDots;
  z += (features.numHyphens             || 0) * MODEL_WEIGHTS.numHyphens;
  z += (features.hasHttps               || 0) * MODEL_WEIGHTS.hasHttps;
  z += (features.hasIpAddress           || 0) * MODEL_WEIGHTS.hasIpAddress;
  z += (features.suspiciousKeywordCount || 0) * MODEL_WEIGHTS.suspiciousKeywordCount;
  z += (features.hasAtSymbol            || 0) * MODEL_WEIGHTS.hasAtSymbol;
  z += (features.numSubdomains          || 0) * MODEL_WEIGHTS.numSubdomains;
  z += (features.hasEncoding            || 0) * MODEL_WEIGHTS.hasEncoding;
  z += (features.domainLength           || 0) * MODEL_WEIGHTS.domainLength;
  z += (features.hasDigitsInDomain      || 0) * MODEL_WEIGHTS.hasDigitsInDomain;
  z += (features.brandInSubdomain       || 0) * MODEL_WEIGHTS.brandInSubdomain;
  z += (features.isTyposquat            || 0) * MODEL_WEIGHTS.isTyposquat;
  z += (features.hasSuspiciousTld       || 0) * MODEL_WEIGHTS.hasSuspiciousTld;
  z += (features.scamKeywordCount       || 0) * MODEL_WEIGHTS.scamKeywordCount;
  z += (features.isLongCompoundDomain   || 0) * MODEL_WEIGHTS.isLongCompoundDomain;

  return sigmoid(z);
}
