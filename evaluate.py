"""
Evaluation script for SachCheck.
Evaluates the deterministic rule engine on the labeled synthetic test dataset.

MANDATORY DATA ETHICS LABEL:
This evaluation represents an 'Internal synthetic test-set evaluation'.
It is NOT real-world accuracy and does NOT claim external verification.
"""

from typing import Dict, Any, List
from analyzer.analyzer import MessageAnalyzer
from data.sample_messages import SYNTHETIC_TEST_SAMPLES, SyntheticSample


def run_evaluation() -> Dict[str, Any]:
    """
    Run evaluation on the labeled synthetic dataset.
    Returns metrics and detailed case results.
    """
    analyzer = MessageAnalyzer()

    total_cases = len(SYNTHETIC_TEST_SAMPLES)
    correctly_classified = 0
    incorrectly_classified = 0
    false_positives = 0
    details: List[Dict[str, Any]] = []

    for sample in SYNTHETIC_TEST_SAMPLES:
        result = analyzer.analyze(sample.text)

        # Check advice detection
        if sample.is_advice:
            is_correct = result.is_advice_request and (result.risk_level == sample.expected_risk_level)
        else:
            # Check risk level
            is_correct = (result.risk_level == sample.expected_risk_level)

            # Check false positive on educational/benign samples
            if not sample.expected_categories and result.indicators:
                false_positives += 1
                is_correct = False

        if is_correct:
            correctly_classified += 1
        else:
            incorrectly_classified += 1

        details.append({
            "id": sample.id,
            "category_focus": sample.category_focus,
            "language": sample.language,
            "expected_risk_level": sample.expected_risk_level,
            "actual_risk_level": result.risk_level,
            "actual_score": result.risk_score,
            "is_correct": is_correct,
            "detected_categories": [ind.category_id for ind in result.indicators],
            "is_advice_request": result.is_advice_request,
            "matched_phrases": result.all_matched_phrases,
        })

    accuracy = (correctly_classified / total_cases * 100) if total_cases > 0 else 0.0

    return {
        "evaluation_label": "Internal synthetic test-set evaluation",
        "total_test_cases": total_cases,
        "correctly_classified": correctly_classified,
        "incorrectly_classified": incorrectly_classified,
        "accuracy_pct": round(accuracy, 2),
        "false_positive_count": false_positives,
        "case_details": details,
    }


def print_evaluation_report(results: Dict[str, Any]) -> None:
    """Print human-readable evaluation report to stdout."""
    print("=" * 70)
    print(f"  {results['evaluation_label'].upper()}")
    print("=" * 70)
    print(f"Total Synthetic Cases : {results['total_test_cases']}")
    print(f"Correctly Classified : {results['correctly_classified']}")
    print(f"Incorrectly Classified: {results['incorrectly_classified']}")
    print(f"Accuracy Rate         : {results['accuracy_pct']}%")
    print(f"False Positives       : {results['false_positive_count']}")
    print("-" * 70)
    print(f"{'ID':<12} {'Lang':<10} {'Exp Level':<10} {'Act Level':<10} {'Score':<6} {'Result'}")
    print("-" * 70)
    for c in results["case_details"]:
        status = "PASS" if c["is_correct"] else "FAIL"
        print(f"{c['id']:<12} {c['language']:<10} {c['expected_risk_level']:<10} {c['actual_risk_level']:<10} {c['actual_score']:<6} {status}")
    print("=" * 70)


if __name__ == "__main__":
    res = run_evaluation()
    print_evaluation_report(res)
