import Card from '../components/common/Card';

const HTTPTraffic = () => {
  return (
    <div className="space-y-6">
      <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
        HTTP Traffic
      </h2>
      <Card>
        <p className="text-gray-600 dark:text-gray-400">
          HTTP traffic logs will be displayed here.
        </p>
      </Card>
    </div>
  );
};

export default HTTPTraffic;
