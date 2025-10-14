import Card from '../components/common/Card';

const ScanDetails = () => {
  return (
    <div className="space-y-6">
      <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
        Scan Details
      </h2>
      <Card>
        <p className="text-gray-600 dark:text-gray-400">
          Detailed scan information will be displayed here.
        </p>
      </Card>
    </div>
  );
};

export default ScanDetails;
